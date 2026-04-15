// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/database"
)

const BackfillMinBackoffAfterRoomCreate = 1 * time.Minute
const BackfillQueueErrorBackoff = 1 * time.Minute
const BackfillQueueMaxEmptyBackoff = 10 * time.Minute

func (br *Bridge) WakeupBackfillQueue(manualTask ...*ManualBackfill) {
	if br.IsStopping() {
		for _, task := range manualTask {
			if task.DoneCallback != nil {
				task.DoneCallback(errBackfillQueueStopped)
			}
		}
		return
	}
	if !br.Config.Backfill.Queue.Enabled {
		for _, task := range manualTask {
			go task.addLogAndDo(task.Portal.Log.WithContext(br.BackgroundCtx))
		}
		return
	}
	for _, task := range manualTask {
		br.manualBackfills <- task
	}
	select {
	case br.wakeupBackfillQueue <- struct{}{}:
	default:
	}
}

type ManualBackfill struct {
	Source *UserLogin
	Portal *Portal
	Data   *FetchMessagesResponse

	DoneCallback func(error)
}

var errBackfillQueueStopped = errors.New("backfill queue stopped")

func (br *Bridge) flushManualBackfillQueue() {
	for {
		select {
		case manualTask := <-br.manualBackfills:
			if manualTask.DoneCallback != nil {
				manualTask.DoneCallback(errBackfillQueueStopped)
			}
		default:
			return
		}
	}
}

func (br *Bridge) RunBackfillQueue() {
	if !br.Config.Backfill.Queue.Enabled || !br.Config.Backfill.Enabled {
		return
	}
	log := br.Log.With().Str("component", "backfill queue").Logger()
	if !br.Matrix.GetCapabilities().BatchSending {
		log.Warn().Msg("Backfill queue is enabled in config, but Matrix server doesn't support batch sending")
		return
	}
	ctx, cancel := context.WithCancel(log.WithContext(context.Background()))
	br.stopBackfillQueue.Clear()
	stopChan := br.stopBackfillQueue.GetChan()
	go func() {
		<-stopChan
		cancel()
	}()
	batchDelay := time.Duration(br.Config.Backfill.Queue.BatchDelay) * time.Second
	log.Info().Stringer("batch_delay", batchDelay).Msg("Backfill queue starting")
	noTasksFoundCount := 0
	for {
		nextDelay := batchDelay
		if noTasksFoundCount > 0 {
			extraDelay := batchDelay * time.Duration(noTasksFoundCount)
			nextDelay += min(BackfillQueueMaxEmptyBackoff, extraDelay)
		}
		select {
		case <-br.wakeupBackfillQueue:
			noTasksFoundCount = 0
		case <-stopChan:
			log.Info().Msg("Stopping backfill queue")
			br.flushManualBackfillQueue()
			return
		case <-time.After(nextDelay):
		}
		select {
		case manualTask := <-br.manualBackfills:
			manualTask.addLogAndDo(ctx)
		default:
			backfillTask, err := br.DB.BackfillTask.GetNext(ctx)
			if err != nil {
				log.Err(err).Msg("Failed to get next backfill queue entry")
				time.Sleep(BackfillQueueErrorBackoff)
				continue
			} else if backfillTask != nil {
				backfillTask.FromQueue = true
				br.DoBackfillTask(ctx, backfillTask)
				noTasksFoundCount = 0
			}
		}
	}
}

func (mt *ManualBackfill) addLogAndDo(ctx context.Context) {
	log := zerolog.Ctx(ctx).With().
		Object("portal_key", mt.Portal.PortalKey).
		Str("login_id", string(mt.Source.ID)).
		Str("task_type", "manual").
		Logger()
	ctx = log.WithContext(ctx)
	mt.Do(ctx)
}

func (mt *ManualBackfill) Do(ctx context.Context) {
	log := zerolog.Ctx(ctx)
	var completed bool
	var err error
	if !mt.Portal.backfillLock.TryLock() {
		log.Warn().Msg("Backfill already in progress")
		mt.Portal.backfillLock.Lock()
	}
	defer mt.Portal.backfillLock.Unlock()
	defer func() {
		if !completed {
			if mt.DoneCallback != nil {
				if mt.Portal.nextBackfillDoneCallback != nil {
					mt.Portal.nextBackfillDoneCallback(errors.New("done callback overridden"))
				}
				mt.Portal.nextBackfillDoneCallback = mt.DoneCallback
				mt.DoneCallback = nil
			}
			return
		}
		if mt.DoneCallback != nil {
			mt.DoneCallback(err)
		}
		if mt.Portal.nextBackfillDoneCallback != nil {
			mt.Portal.nextBackfillDoneCallback(err)
			mt.Portal.nextBackfillDoneCallback = nil
		}
	}()
	var task *database.BackfillTask
	task, err = mt.Portal.Bridge.DB.BackfillTask.GetNextForPortal(ctx, mt.Portal.PortalKey, mt.Data != nil)
	if err != nil {
		log.Err(err).Msg("Failed to get backfill task from database")
	} else if task == nil {
		log.Warn().Msg("No backfill task found for portal")
	} else if err = mt.Portal.Bridge.DB.BackfillTask.MarkDispatched(ctx, task); err != nil {
		log.Err(err).Msg("Failed to mark backfill task as dispatched")
	} else if completed, err = mt.Portal.doBackfillTask(ctx, mt.Source, task, mt.Data); err != nil {
		log.Err(err).Msg("Failed to do backwards backfill from event")
	} else {
		log.Debug().Bool("completed", completed).Msg("Finished backfill from event")
		err = mt.Portal.Bridge.DB.BackfillTask.Update(ctx, task)
		if err != nil {
			log.Err(err).Msg("Failed to update backfill task in database after backfill")
		}
	}
}

func (br *Bridge) DoBackfillTask(ctx context.Context, task *database.BackfillTask) {
	log := zerolog.Ctx(ctx).With().
		Object("portal_key", task.PortalKey).
		Str("login_id", string(task.UserLoginID)).
		Logger()
	defer func() {
		err := recover()
		if err != nil {
			logEvt := log.Error().
				Bytes(zerolog.ErrorStackFieldName, debug.Stack())
			if realErr, ok := err.(error); ok {
				logEvt = logEvt.Err(realErr)
			} else {
				logEvt = logEvt.Any(zerolog.ErrorFieldName, err)
			}
			logEvt.Msg("Panic in backfill queue")
		}
	}()
	ctx = log.WithContext(ctx)
	err := br.DB.BackfillTask.MarkDispatched(ctx, task)
	if err != nil {
		log.Err(err).Msg("Failed to mark backfill task as dispatched")
		time.Sleep(BackfillQueueErrorBackoff)
		return
	}
	completed, err := br.getPortalAndDoBackfillTask(ctx, task)
	if err != nil {
		log.Err(err).Msg("Failed to do backfill task")
		time.Sleep(BackfillQueueErrorBackoff)
		return
	} else if completed {
		log.Info().
			Int("batch_count", task.BatchCount).
			Bool("is_done", task.IsDone).
			Msg("Backfill task completed successfully")
	} else {
		log.Info().
			Int("batch_count", task.BatchCount).
			Bool("is_done", task.IsDone).
			Msg("Backfill task not completed")
	}
	err = br.DB.BackfillTask.Update(ctx, task)
	if err != nil {
		log.Err(err).Msg("Failed to update backfill task")
		time.Sleep(BackfillQueueErrorBackoff)
	}
}

func (portal *Portal) deleteBackfillQueueTaskIfRoomDoesNotExist(ctx context.Context) bool {
	// Acquire the room create lock to ensure that task deletion doesn't race with room creation
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	if portal.MXID == "" {
		zerolog.Ctx(ctx).Debug().Msg("Portal for backfill task doesn't exist, deleting entry")
		err := portal.Bridge.DB.BackfillTask.Delete(ctx, portal.PortalKey)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to delete backfill task after portal wasn't found")
		}
		return true
	}
	return false
}

func (br *Bridge) getPortalAndDoBackfillTask(ctx context.Context, task *database.BackfillTask) (bool, error) {
	log := zerolog.Ctx(ctx)
	portal, err := br.GetExistingPortalByKey(ctx, task.PortalKey)
	if err != nil {
		return false, fmt.Errorf("failed to get portal for backfill task: %w", err)
	} else if portal == nil {
		log.Warn().Msg("Portal not found for backfill task")
		err = br.DB.BackfillTask.Delete(ctx, task.PortalKey)
		if err != nil {
			log.Err(err).Msg("Failed to delete backfill task after portal wasn't found")
			time.Sleep(BackfillQueueErrorBackoff)
		}
		return false, nil
	} else if portal.MXID == "" {
		portal.deleteBackfillQueueTaskIfRoomDoesNotExist(ctx)
		return false, nil
	}
	login, err := br.GetExistingUserLoginByID(ctx, task.UserLoginID)
	if err != nil {
		return false, fmt.Errorf("failed to get user login for backfill task: %w", err)
	} else if login == nil || !login.Client.IsLoggedIn() {
		if login == nil {
			log.Warn().Msg("User login not found for backfill task")
		} else {
			log.Warn().Msg("User login not logged in for backfill task")
		}
		logins, err := br.GetUserLoginsInPortal(ctx, portal.PortalKey)
		if err != nil {
			return false, fmt.Errorf("failed to get user portals for backfill task: %w", err)
		} else if len(logins) == 0 {
			log.Debug().Msg("No user logins found for backfill task")
			task.NextDispatchMinTS = database.BackfillNextDispatchNever
			if login == nil {
				task.UserLoginID = ""
			}
			return false, nil
		}
		if login == nil {
			task.UserLoginID = ""
		}
		foundLogin := false
		for _, login = range logins {
			if login.Client.IsLoggedIn() {
				foundLogin = true
				task.UserLoginID = login.ID
				log.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str("overridden_login_id", string(login.ID))
				})
				log.Debug().Msg("Found user login for backfill task")
				break
			}
		}
		if !foundLogin {
			log.Debug().Msg("No logged in user logins found for backfill task")
			task.NextDispatchMinTS = database.BackfillNextDispatchNever
			return false, nil
		}
	}
	if task.BatchCount < 0 {
		var msgCount int
		msgCount, err = br.DB.Message.CountMessagesInPortal(ctx, task.PortalKey)
		if err != nil {
			return false, fmt.Errorf("failed to count messages in portal: %w", err)
		}
		task.BatchCount = msgCount / br.Config.Backfill.Queue.BatchSize
		log.Debug().
			Int("message_count", msgCount).
			Int("batch_count", task.BatchCount).
			Msg("Calculated existing batch count")
	}
	if !portal.backfillLock.TryLock() {
		zerolog.Ctx(ctx).Warn().Msg("Backfill already in progress")
		portal.backfillLock.Lock()
	}
	defer portal.backfillLock.Unlock()
	return portal.doBackfillTask(ctx, login, task, nil)
}

func (portal *Portal) doBackfillTask(ctx context.Context, source *UserLogin, task *database.BackfillTask, resp *FetchMessagesResponse) (bool, error) {
	maxBatches := portal.Bridge.Config.Backfill.Queue.MaxBatches
	api, ok := source.Client.(BackfillingNetworkAPI)
	if !ok {
		return false, fmt.Errorf("network API does not support backfilling")
	}
	limiterAPI, ok := api.(BackfillingNetworkAPIWithLimits)
	if ok {
		maxBatches = limiterAPI.GetBackfillMaxBatchCount(ctx, portal, task)
	}
	if maxBatches < 0 || maxBatches > task.BatchCount {
		pending, err := portal.doBackwardsBackfill(ctx, source, task, resp)
		if err != nil {
			return false, fmt.Errorf("failed to backfill: %w", err)
		} else if pending {
			return false, nil
		}
		task.BatchCount++
	} else {
		zerolog.Ctx(ctx).Debug().
			Int("max_batches", maxBatches).
			Int("batch_count", task.BatchCount).
			Msg("Not actually backfilling: max batches reached")
	}
	task.IsDone = task.IsDone || (maxBatches > 0 && task.BatchCount >= maxBatches)
	task.QueueDone = task.IsDone || task.QueueDone
	batchDelay := time.Duration(portal.Bridge.Config.Backfill.Queue.BatchDelay) * time.Second
	task.CompletedAt = time.Now()
	task.NextDispatchMinTS = task.CompletedAt.Add(batchDelay)
	return true, nil
}
