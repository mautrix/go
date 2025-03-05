// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/database"
)

const BackfillMinBackoffAfterRoomCreate = 1 * time.Minute
const BackfillQueueErrorBackoff = 1 * time.Minute
const BackfillQueueMaxEmptyBackoff = 10 * time.Minute

func (br *Bridge) WakeupBackfillQueue() {
	select {
	case br.wakeupBackfillQueue <- struct{}{}:
	default:
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
		timer := time.NewTimer(nextDelay)
		select {
		case <-br.wakeupBackfillQueue:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			noTasksFoundCount = 0
		case <-stopChan:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			log.Info().Msg("Stopping backfill queue")
			return
		case <-timer.C:
		}
		backfillTask, err := br.DB.BackfillTask.GetNext(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to get next backfill queue entry")
			time.Sleep(BackfillQueueErrorBackoff)
			continue
		} else if backfillTask != nil {
			br.DoBackfillTask(ctx, backfillTask)
			noTasksFoundCount = 0
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
	completed, err := br.actuallyDoBackfillTask(ctx, task)
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
			Msg("Backfill task canceled")
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

func (br *Bridge) actuallyDoBackfillTask(ctx context.Context, task *database.BackfillTask) (bool, error) {
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
	maxBatches := br.Config.Backfill.Queue.MaxBatches
	api, ok := login.Client.(BackfillingNetworkAPI)
	if !ok {
		return false, fmt.Errorf("network API does not support backfilling")
	}
	limiterAPI, ok := api.(BackfillingNetworkAPIWithLimits)
	if ok {
		maxBatches = limiterAPI.GetBackfillMaxBatchCount(ctx, portal, task)
	}
	if maxBatches < 0 || maxBatches > task.BatchCount {
		err = portal.DoBackwardsBackfill(ctx, login, task)
		if err != nil {
			return false, fmt.Errorf("failed to backfill: %w", err)
		}
		task.BatchCount++
	} else {
		log.Debug().
			Int("max_batches", maxBatches).
			Int("batch_count", task.BatchCount).
			Msg("Not actually backfilling: max batches reached")
	}
	task.IsDone = task.IsDone || (maxBatches > 0 && task.BatchCount >= maxBatches)
	batchDelay := time.Duration(br.Config.Backfill.Queue.BatchDelay) * time.Second
	task.CompletedAt = time.Now()
	task.NextDispatchMinTS = task.CompletedAt.Add(batchDelay)
	return true, nil
}
