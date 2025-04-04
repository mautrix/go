// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mxmain

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/matrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (br *BridgeMain) LegacyMigrateWithAnotherUpgrader(renameTablesQuery, copyDataQuery string, newDBVersion int, otherTable dbutil.UpgradeTable, otherTableName string, otherNewVersion int) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		// Unique constraints must have globally unique names on postgres, and renaming the table doesn't rename them,
		// so just drop the ones that may conflict with the new schema.
		if br.DB.Dialect == dbutil.Postgres {
			_, err := br.DB.Exec(ctx, "ALTER TABLE message DROP CONSTRAINT IF EXISTS message_mxid_unique")
			if err != nil {
				return fmt.Errorf("failed to drop potentially conflicting constraint on message: %w", err)
			}
			_, err = br.DB.Exec(ctx, "ALTER TABLE reaction DROP CONSTRAINT IF EXISTS reaction_mxid_unique")
			if err != nil {
				return fmt.Errorf("failed to drop potentially conflicting constraint on reaction: %w", err)
			}
		}
		err := dbutil.DangerousInternalUpgradeVersionTable(ctx, br.DB)
		if err != nil {
			return err
		}
		_, err = br.DB.Exec(ctx, renameTablesQuery)
		if err != nil {
			return err
		}
		upgradesTo, compat, err := br.DB.UpgradeTable[0].DangerouslyRun(ctx, br.DB)
		if err != nil {
			return err
		}
		if upgradesTo < newDBVersion || compat > newDBVersion {
			return fmt.Errorf("unexpected new database version (%d/c:%d, expected %d)", upgradesTo, compat, newDBVersion)
		}
		if otherTable != nil {
			_, err = br.DB.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (version INTEGER, compat INTEGER)", otherTableName))
			if err != nil {
				return err
			}
			otherUpgradesTo, otherCompat, err := otherTable[0].DangerouslyRun(ctx, br.DB)
			if err != nil {
				return err
			} else if otherUpgradesTo < otherNewVersion || otherCompat > otherNewVersion {
				return fmt.Errorf("unexpected new database version for %s (%d/c:%d, expected %d)", otherTableName, otherUpgradesTo, otherCompat, otherNewVersion)
			}
			_, err = br.DB.Exec(ctx, fmt.Sprintf("INSERT INTO %s (version, compat) VALUES ($1, $2)", otherTableName), otherUpgradesTo, otherCompat)
			if err != nil {
				return err
			}
		}
		copyDataQuery, err = br.DB.Internals().FilterSQLUpgrade(bytes.Split([]byte(copyDataQuery), []byte("\n")))
		if err != nil {
			return err
		}
		_, err = br.DB.Exec(ctx, copyDataQuery)
		if err != nil {
			return err
		}
		_, err = br.DB.Exec(ctx, "DELETE FROM database_owner")
		if err != nil {
			return err
		}
		_, err = br.DB.Exec(ctx, "INSERT INTO database_owner (key, owner) VALUES (0, $1)", br.DB.Owner)
		if err != nil {
			return err
		}
		_, err = br.DB.Exec(ctx, "DELETE FROM version")
		if err != nil {
			return err
		}
		_, err = br.DB.Exec(ctx, "INSERT INTO version (version, compat) VALUES ($1, $2)", upgradesTo, compat)
		if err != nil {
			return err
		}
		_, err = br.DB.Exec(ctx, "CREATE TABLE database_was_migrated(empty INTEGER)")
		if err != nil {
			return err
		}

		return nil
	}
}

func (br *BridgeMain) LegacyMigrateSimple(renameTablesQuery, copyDataQuery string, newDBVersion int) func(ctx context.Context) error {
	return br.LegacyMigrateWithAnotherUpgrader(renameTablesQuery, copyDataQuery, newDBVersion, nil, "", 0)
}

func (br *BridgeMain) CheckLegacyDB(
	expectedVersion int,
	minBridgeVersion,
	firstMegaVersion string,
	migrator func(context.Context) error,
	transaction bool,
) {
	log := br.Log.With().Str("action", "migrate legacy db").Logger()
	ctx := log.WithContext(context.Background())
	exists, err := br.DB.TableExists(ctx, "database_owner")
	if err != nil {
		log.Err(err).Msg("Failed to check if database_owner table exists")
		return
	} else if !exists {
		return
	}
	var owner string
	err = br.DB.QueryRow(ctx, "SELECT owner FROM database_owner LIMIT 1").Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Err(err).Msg("Failed to get database owner")
		return
	} else if owner != br.Name {
		if owner != "megabridge/"+br.Name && owner != "" {
			log.Warn().Str("db_owner", owner).Msg("Unexpected database owner, not migrating database")
		}
		return
	}
	var dbVersion int
	err = br.DB.QueryRow(ctx, "SELECT version FROM version").Scan(&dbVersion)
	if dbVersion < expectedVersion {
		log.Fatal().
			Int("expected_version", expectedVersion).
			Int("version", dbVersion).
			Msgf("Unsupported database version. Please upgrade to %s %s or higher before upgrading to %s.", br.Name, minBridgeVersion, firstMegaVersion) // zerolog-allow-msgf
		return
	} else if dbVersion > expectedVersion {
		log.Fatal().
			Int("expected_version", expectedVersion).
			Int("version", dbVersion).
			Msg("Unsupported database version (higher than expected)")
		return
	}
	log.Info().Msg("Detected legacy database, migrating...")
	if transaction {
		err = br.DB.DoTxn(ctx, nil, migrator)
	} else {
		err = migrator(ctx)
	}
	if err != nil {
		br.LogDBUpgradeErrorAndExit("main", err, "Failed to migrate legacy database")
	} else {
		log.Info().Msg("Successfully migrated legacy database")
	}
}

func (br *BridgeMain) postMigrateDMPortal(ctx context.Context, portal *bridgev2.Portal) error {
	otherUserID := portal.OtherUserID
	if otherUserID == "" {
		zerolog.Ctx(ctx).Warn().
			Str("portal_id", string(portal.ID)).
			Msg("DM portal has no other user ID")
		return nil
	}
	ghost, err := br.Bridge.GetGhostByID(ctx, otherUserID)
	if err != nil {
		return fmt.Errorf("failed to get ghost for %s: %w", otherUserID, err)
	}
	mx := ghost.Intent.(*matrix.ASIntent).Matrix
	err = br.Matrix.Bot.EnsureJoined(ctx, portal.MXID, appservice.EnsureJoinedParams{
		BotOverride: mx.Client,
	})
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Str("portal_id", string(portal.ID)).
			Stringer("room_id", portal.MXID).
			Msg("Failed to ensure bot is joined to DM")
	}
	pls, err := mx.PowerLevels(ctx, portal.MXID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Str("portal_id", string(portal.ID)).
			Stringer("room_id", portal.MXID).
			Msg("Failed to get power levels in room")
	} else {
		userLevel := pls.GetUserLevel(mx.UserID)
		pls.EnsureUserLevel(br.Matrix.Bot.UserID, userLevel)
		if userLevel > 50 {
			pls.SetUserLevel(mx.UserID, 50)
		}
		_, err = mx.SetPowerLevels(ctx, portal.MXID, pls)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Str("portal_id", string(portal.ID)).
				Stringer("room_id", portal.MXID).
				Msg("Failed to set power levels")
		}
	}
	portal.UpdateInfoFromGhost(ctx, ghost)
	return nil
}

func (br *BridgeMain) PostMigrate(ctx context.Context) error {
	log := br.Log.With().Str("action", "post-migrate").Logger()
	wasMigrated, err := br.DB.TableExists(ctx, "database_was_migrated")
	if err != nil {
		return fmt.Errorf("failed to check if database_was_migrated table exists: %w", err)
	} else if !wasMigrated {
		return nil
	}
	log.Info().Msg("Doing post-migration updates to Matrix rooms")

	portals, err := br.Bridge.GetAllPortalsWithMXID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get all portals: %w", err)
	}
	for _, portal := range portals {
		log := log.With().
			Stringer("room_id", portal.MXID).
			Object("portal_key", portal.PortalKey).
			Str("room_type", string(portal.RoomType)).
			Logger()
		log.Debug().Msg("Migrating portal")
		if br.PostMigratePortal != nil {
			err = br.PostMigratePortal(ctx, portal)
			if err != nil {
				log.Err(err).Msg("Failed to run post-migrate portal hook")
				continue
			}
		} else {
			switch portal.RoomType {
			case database.RoomTypeDM:
				err = br.postMigrateDMPortal(ctx, portal)
				if err != nil {
					return fmt.Errorf("failed to update DM portal %s: %w", portal.MXID, err)
				}
			}
		}
		_, err = br.Matrix.Bot.SendStateEvent(ctx, portal.MXID, event.StateElementFunctionalMembers, "", &event.ElementFunctionalMembersContent{
			ServiceMembers: []id.UserID{br.Matrix.Bot.UserID},
		})
		if err != nil {
			log.Warn().Err(err).Stringer("room_id", portal.MXID).Msg("Failed to set service members")
		}
	}

	_, err = br.DB.Exec(ctx, "DROP TABLE database_was_migrated")
	if err != nil {
		return fmt.Errorf("failed to drop database_was_migrated table: %w", err)
	}
	log.Info().Msg("Post-migration updates complete")
	return nil
}
