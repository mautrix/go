package sql_store_upgrade

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type upgradeFunc func(*sql.Tx, string) error

var ErrUnknownDialect = errors.New("unknown dialect")

var Upgrades = [...]upgradeFunc{
	func(tx *sql.Tx, _ string) error {
		for _, query := range []string{
			`CREATE TABLE IF NOT EXISTS crypto_account (
				device_id  VARCHAR(255) PRIMARY KEY,
				shared     BOOLEAN      NOT NULL,
				sync_token TEXT         NOT NULL,
				account    bytea        NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS crypto_message_index (
				sender_key CHAR(43),
				session_id CHAR(43),
				"index"    INTEGER,
				event_id   VARCHAR(255) NOT NULL,
				timestamp  BIGINT       NOT NULL,
				PRIMARY KEY (sender_key, session_id, "index")
			)`,
			`CREATE TABLE IF NOT EXISTS crypto_tracked_user (
				user_id VARCHAR(255) PRIMARY KEY
			)`,
			`CREATE TABLE IF NOT EXISTS crypto_device (
				user_id      VARCHAR(255),
				device_id    VARCHAR(255),
				identity_key CHAR(43)      NOT NULL,
				signing_key  CHAR(43)      NOT NULL,
				trust        SMALLINT      NOT NULL,
				deleted      BOOLEAN       NOT NULL,
				name         VARCHAR(255)  NOT NULL,
				PRIMARY KEY (user_id, device_id)
			)`,
			`CREATE TABLE IF NOT EXISTS crypto_olm_session (
				session_id   CHAR(43)  PRIMARY KEY,
				sender_key   CHAR(43)  NOT NULL,
				session      bytea     NOT NULL,
				created_at   timestamp NOT NULL,
				last_used    timestamp NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS crypto_megolm_inbound_session (
				session_id   CHAR(43)     PRIMARY KEY,
				sender_key   CHAR(43)     NOT NULL,
				signing_key  CHAR(43)     NOT NULL,
				room_id      VARCHAR(255) NOT NULL,
				session      bytea        NOT NULL,
				forwarding_chains bytea   NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS crypto_megolm_outbound_session (
				room_id       VARCHAR(255) PRIMARY KEY,
				session_id    CHAR(43)     NOT NULL UNIQUE,
				session       bytea        NOT NULL,
				shared        BOOLEAN      NOT NULL,
				max_messages  INTEGER      NOT NULL,
				message_count INTEGER      NOT NULL,
				max_age       BIGINT       NOT NULL,
				created_at    timestamp    NOT NULL,
				last_used     timestamp    NOT NULL
			)`,
		} {
			if _, err := tx.Exec(query); err != nil {
				return err
			}
		}
		return nil
	},
	func(tx *sql.Tx, dialect string) error {
		if dialect == "postgres" {
			tablesToPkeys := map[string][]string{
				"crypto_account":                 {},
				"crypto_olm_session":             {"session_id"},
				"crypto_megolm_inbound_session":  {"session_id"},
				"crypto_megolm_outbound_session": {"room_id"},
			}
			for tableName, pkeys := range tablesToPkeys {
				// add account_id to primary key
				pkeyStr := strings.Join(append(pkeys, "account_id"), ", ")
				for _, query := range []string{
					fmt.Sprintf("ALTER TABLE %s ADD COLUMN account_id VARCHAR(255)", tableName),
					fmt.Sprintf("UPDATE %s SET account_id=''", tableName),
					fmt.Sprintf("ALTER TABLE %s ALTER COLUMN account_id SET NOT NULL", tableName),
					fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s_pkey", tableName, tableName),
					fmt.Sprintf("ALTER TABLE %s ADD CONSTRAINT %s_pkey PRIMARY KEY (%s)", tableName, tableName, pkeyStr),
				} {
					if _, err := tx.Exec(query); err != nil {
						return err
					}
				}
			}
		} else if dialect == "sqlite3" {
			tableCols := map[string]string{
				"crypto_account": `
					account_id VARCHAR(255) NOT NULL,
					device_id  VARCHAR(255) NOT NULL,
					shared     BOOLEAN      NOT NULL,
					sync_token TEXT         NOT NULL,
					account    BLOB         NOT NULL,
					PRIMARY KEY (account_id)
				`,
				"crypto_olm_session": `
					account_id   VARCHAR(255) NOT NULL,
					session_id   CHAR(43)     NOT NULL,
					sender_key   CHAR(43)     NOT NULL,
					session      BLOB         NOT NULL,
					created_at   timestamp    NOT NULL,
					last_used    timestamp    NOT NULL,
					PRIMARY KEY (account_id, session_id)
				`,
				"crypto_megolm_inbound_session": `
					account_id   VARCHAR(255) NOT NULL,
					session_id   CHAR(43)     NOT NULL,
					sender_key   CHAR(43)     NOT NULL,
					signing_key  CHAR(43)     NOT NULL,
					room_id      VARCHAR(255) NOT NULL,
					session      BLOB         NOT NULL,
					forwarding_chains BLOB    NOT NULL,
					PRIMARY KEY (account_id, session_id)
				`,
				"crypto_megolm_outbound_session": `
					account_id    VARCHAR(255) NOT NULL,
					room_id       VARCHAR(255) NOT NULL,
					session_id    CHAR(43)     NOT NULL UNIQUE,
					session       BLOB         NOT NULL,
					shared        BOOLEAN      NOT NULL,
					max_messages  INTEGER      NOT NULL,
					message_count INTEGER      NOT NULL,
					max_age       BIGINT       NOT NULL,
					created_at    timestamp    NOT NULL,
					last_used     timestamp    NOT NULL,
					PRIMARY KEY (account_id, room_id)
				`,
			}
			for tableName, cols := range tableCols {
				// re-create tables with account_id column and new pkey and re-insert rows
				for _, query := range []string{
					fmt.Sprintf("ALTER TABLE %s RENAME TO old_%s", tableName, tableName),
					fmt.Sprintf("CREATE TABLE %s (%s)", tableName, cols),
					fmt.Sprintf("INSERT INTO %s SELECT '', * FROM old_%s", tableName, tableName),
					fmt.Sprintf("DROP TABLE old_%s", tableName),
				} {
					if _, err := tx.Exec(query); err != nil {
						return err
					}
				}
			}
		} else {
			return fmt.Errorf("%w (%s)", ErrUnknownDialect, dialect)
		}
		return nil
	},
	func(tx *sql.Tx, dialect string) error {
		if dialect == "postgres" {
			alters := [...]string{
				"ADD COLUMN withheld_code VARCHAR(255)",
				"ADD COLUMN withheld_reason TEXT",
				"ALTER COLUMN signing_key DROP NOT NULL",
				"ALTER COLUMN session DROP NOT NULL",
				"ALTER COLUMN forwarding_chains DROP NOT NULL",
			}
			for _, alter := range alters {
				_, err := tx.Exec(fmt.Sprintf("ALTER TABLE crypto_megolm_inbound_session %s", alter))
				if err != nil {
					return err
				}
			}
		} else if dialect == "sqlite3" {
			_, err := tx.Exec("ALTER TABLE crypto_megolm_inbound_session RENAME TO old_crypto_megolm_inbound_session")
			if err != nil {
				return err
			}
			_, err = tx.Exec(`CREATE TABLE crypto_megolm_inbound_session (
				account_id   VARCHAR(255) NOT NULL,
				session_id   CHAR(43)     NOT NULL,
				sender_key   CHAR(43)     NOT NULL,
				signing_key  CHAR(43),
				room_id      VARCHAR(255) NOT NULL,
				session           BLOB,
				forwarding_chains BLOB,
				withheld_code     VARCHAR(255),
				withheld_reason   TEXT,
				PRIMARY KEY (account_id, session_id)
			)`)
			if err != nil {
				return err
			}
			_, err = tx.Exec(`INSERT INTO crypto_megolm_inbound_session
				(session_id, sender_key, signing_key, room_id, session, forwarding_chains, account_id)
				SELECT * FROM old_crypto_megolm_inbound_session`)
			if err != nil {
				return err
			}
			_, err = tx.Exec("DROP TABLE old_crypto_megolm_inbound_session")
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("%w (%s)", ErrUnknownDialect, dialect)
		}
		return nil
	},
	func(tx *sql.Tx, dialect string) error {
		if _, err := tx.Exec(
			`CREATE TABLE IF NOT EXISTS crypto_cross_signing_keys (
				user_id VARCHAR(255) NOT NULL,
				usage   VARCHAR(20)  NOT NULL,
				key     CHAR(43)     NOT NULL,
				PRIMARY KEY (user_id, usage)
			)`,
		); err != nil {
			return err
		}
		if _, err := tx.Exec(
			`CREATE TABLE IF NOT EXISTS crypto_cross_signing_signatures (
				signed_user_id VARCHAR(255) NOT NULL,
				signed_key     VARCHAR(255) NOT NULL,
				signer_user_id VARCHAR(255) NOT NULL,
				signer_key     VARCHAR(255) NOT NULL,
				signature      CHAR(88)     NOT NULL,
				PRIMARY KEY (signed_user_id, signed_key, signer_user_id, signer_key)
			)`,
		); err != nil {
			return err
		}
		return nil
	},
	func(tx *sql.Tx, dialect string) error {
		if dialect == "sqlite3" {
			// SQLite doesn't enforce varchar sizes anyway
			return nil
		}
		alters := [...]string{
			`ALTER TABLE crypto_account ALTER COLUMN device_id TYPE TEXT`,
			`ALTER TABLE crypto_account ALTER COLUMN account_id TYPE TEXT`,

			`ALTER TABLE crypto_device ALTER COLUMN user_id TYPE TEXT`,
			`ALTER TABLE crypto_device ALTER COLUMN device_id TYPE TEXT`,
			`ALTER TABLE crypto_device ALTER COLUMN name TYPE TEXT`,

			`ALTER TABLE crypto_megolm_inbound_session ALTER COLUMN room_id TYPE TEXT`,
			`ALTER TABLE crypto_megolm_inbound_session ALTER COLUMN account_id TYPE TEXT`,
			`ALTER TABLE crypto_megolm_inbound_session ALTER COLUMN withheld_code TYPE TEXT`,

			`ALTER TABLE crypto_megolm_outbound_session ALTER COLUMN room_id TYPE TEXT`,
			`ALTER TABLE crypto_megolm_outbound_session ALTER COLUMN account_id TYPE TEXT`,

			`ALTER TABLE crypto_message_index ALTER COLUMN event_id TYPE TEXT`,

			`ALTER TABLE crypto_olm_session ALTER COLUMN account_id TYPE TEXT`,

			`ALTER TABLE crypto_tracked_user ALTER COLUMN user_id TYPE TEXT`,

			`ALTER TABLE crypto_cross_signing_keys ALTER COLUMN user_id TYPE TEXT`,
			`ALTER TABLE crypto_cross_signing_keys ALTER COLUMN usage TYPE TEXT`,

			`ALTER TABLE crypto_cross_signing_signatures ALTER COLUMN signed_user_id TYPE TEXT`,
			`ALTER TABLE crypto_cross_signing_signatures ALTER COLUMN signed_key TYPE TEXT`,
			`ALTER TABLE crypto_cross_signing_signatures ALTER COLUMN signer_user_id TYPE TEXT`,
			`ALTER TABLE crypto_cross_signing_signatures ALTER COLUMN signer_key TYPE TEXT`,
			`ALTER TABLE crypto_cross_signing_signatures ALTER COLUMN signature TYPE TEXT`,
		}
		for _, alter := range alters {
			_, err := tx.Exec(alter)
			if err != nil {
				return err
			}
		}
		return nil
	},
}

// GetVersion returns the current version of the DB schema.
func GetVersion(db *sql.DB) (int, error) {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS crypto_version (version INTEGER)")
	if err != nil {
		return -1, err
	}

	version := 0
	row := db.QueryRow("SELECT version FROM crypto_version LIMIT 1")
	if row != nil {
		_ = row.Scan(&version)
	}
	return version, nil
}

// SetVersion sets the schema version in a running DB transaction.
func SetVersion(tx *sql.Tx, version int) error {
	_, err := tx.Exec("DELETE FROM crypto_version")
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO crypto_version (version) VALUES ($1)", version)
	return err
}

// Upgrade upgrades the database from the current to the latest version available.
func Upgrade(db *sql.DB, dialect string) error {
	version, err := GetVersion(db)
	if err != nil {
		return err
	}

	// perform migrations starting with #version
	for ; version < len(Upgrades); version++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}

		// run each migrate func
		migrateFunc := Upgrades[version]
		err = migrateFunc(tx, dialect)
		if err != nil {
			_ = tx.Rollback()
			return err
		}

		// also update the version in this tx
		if err = SetVersion(tx, version+1); err != nil {
			return err
		}

		if err = tx.Commit(); err != nil {
			return err
		}
	}

	return nil
}
