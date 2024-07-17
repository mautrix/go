// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/database"
)

func (br *Bridge) WakeupBackfillQueue() {
	select {
	case br.wakeupBackfillQueue <- struct{}{}:
	default:
	}
}

func (br *Bridge) RunBackfillQueue() {
	if !br.Matrix.GetCapabilities().BatchSending {
		return
	}
	log := br.Log.With().Str("component", "backfill queue").Logger()
	ctx := log.WithContext(context.Background())
	batchDelay := time.Duration(br.Config.Backfill.Queue.BatchDelay) * time.Second
	afterTimer := time.NewTimer(batchDelay)
	for {
		backfillTask, err := br.DB.BackfillQueue.GetNext(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to get next backfill queue entry")
			time.Sleep(1 * time.Minute)
			continue
		} else if backfillTask != nil {
			br.doBackfillTask(ctx, backfillTask)
		}
		nextDelay := batchDelay
		if backfillTask == nil {
			nextDelay = max(10*time.Minute, batchDelay)
		}
		if !afterTimer.Stop() {
			<-afterTimer.C
		}
		afterTimer.Reset(nextDelay)
		select {
		case <-br.wakeupBackfillQueue:
		case <-afterTimer.C:
		}
	}
}

func (br *Bridge) doBackfillTask(ctx context.Context, task *database.BackfillTask) {
	log := zerolog.Ctx(ctx).With().
		Object("portal_key", task.PortalKey).
		Str("login_id", string(task.UserLoginID)).
		Logger()
	err := br.DB.BackfillQueue.MarkDispatched(ctx, task)
	if err != nil {
		log.Err(err).Msg("Failed to mark backfill task as dispatched")
		time.Sleep(1 * time.Minute)
		return
	}
	completed, err := br.actuallyDoBackfillTask(ctx, task)
	if err != nil {
		log.Err(err).Msg("Failed to do backfill task")
		time.Sleep(1 * time.Minute)
		return
	} else if completed {
		log.Info().Msg("Backfill task completed successfully")
	} else {
		log.Info().Msg("Backfill task canceled")
	}
	err = br.DB.BackfillQueue.Update(ctx, task)
	if err != nil {
		log.Err(err).Msg("Failed to update backfill task")
		time.Sleep(1 * time.Minute)
	}
}

func (br *Bridge) actuallyDoBackfillTask(ctx context.Context, task *database.BackfillTask) (bool, error) {
	log := zerolog.Ctx(ctx)
	portal, err := br.GetExistingPortalByKey(ctx, task.PortalKey)
	if err != nil {
		return false, fmt.Errorf("failed to get portal for backfill task: %w", err)
	} else if portal == nil {
		log.Warn().Msg("Portal not found for backfill task")
		err = br.DB.BackfillQueue.Delete(ctx, task.PortalKey)
		if err != nil {
			log.Err(err).Msg("Failed to delete backfill task after portal wasn't found")
			time.Sleep(1 * time.Minute)
		}
		return false, nil
	} else if portal.MXID == "" {
		log.Debug().Msg("Portal for backfill task doesn't exist")
		task.NextDispatchMinTS = database.BackfillNextDispatchNever
		task.UserLoginID = ""
		return false, nil
	}
	login, err := br.GetExistingUserLoginByID(ctx, task.UserLoginID)
	if err != nil {
		return false, fmt.Errorf("failed to get user login for backfill task: %w", err)
	} else if login == nil {
		log.Warn().Msg("User login not found for backfill task")
		logins, err := br.GetUserLoginsInPortal(ctx, portal.PortalKey)
		if err != nil {
			return false, fmt.Errorf("failed to get user portals for backfill task: %w", err)
		} else if len(logins) == 0 {
			log.Debug().Msg("No user logins found for backfill task")
			task.NextDispatchMinTS = database.BackfillNextDispatchNever
			task.UserLoginID = ""
			return false, nil
		}
		task.UserLoginID = ""
		for _, login = range logins {
			if login.Client.IsLoggedIn() {
				task.UserLoginID = login.ID
				log.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str("overridden_login_id", string(login.ID))
				})
				log.Debug().Msg("Found user login for backfill task")
				break
			}
		}
		if task.UserLoginID == "" {
			log.Debug().Msg("No logged in user logins found for backfill task")
			task.NextDispatchMinTS = database.BackfillNextDispatchNever
			return false, nil
		}
	}
	maxBatches := br.Config.Backfill.Queue.MaxBatches
	// TODO apply max batch overrides
	// TODO actually backfill
	hasMoreMessages := true
	task.BatchCount++
	task.IsDone = task.BatchCount >= maxBatches || !hasMoreMessages
	batchDelay := time.Duration(br.Config.Backfill.Queue.BatchDelay) * time.Second
	task.CompletedAt = time.Now()
	task.NextDispatchMinTS = task.CompletedAt.Add(batchDelay)
	return true, nil
}
