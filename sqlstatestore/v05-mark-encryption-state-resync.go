package sqlstatestore

import (
	"context"
	"fmt"

	"go.mau.fi/util/dbutil"
)

func init() {
	UpgradeTable.Register(-1, 5, 0, "Mark rooms that need crypto state event resynced", dbutil.TxnModeOn, func(ctx context.Context, db *dbutil.Database) error {
		portalExists, err := db.TableExists(ctx, "portal")
		if err != nil {
			return fmt.Errorf("failed to check if portal table exists")
		}
		if portalExists {
			_, err = db.Exec(ctx, `
				INSERT INTO mx_room_state (room_id, encryption)
				SELECT portal.mxid, '{"resync":true}' FROM portal WHERE portal.encrypted=true AND portal.mxid IS NOT NULL
				ON CONFLICT (room_id) DO UPDATE
					SET encryption=excluded.encryption
					WHERE mx_room_state.encryption IS NULL
			`)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
