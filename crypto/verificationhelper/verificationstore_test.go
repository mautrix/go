package verificationhelper_test

import (
	"context"
	"database/sql"
	"errors"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/id"
)

type SQLiteVerificationStore struct {
	db *sql.DB
}

const (
	selectVerifications            = `SELECT transaction_data FROM verifications`
	getVerificationByTransactionID = selectVerifications + ` WHERE transaction_id = ?1`
	getVerificationByUserDeviceID  = selectVerifications + `
		WHERE transaction_data->>'their_user_id' = ?1
		  AND transaction_data->>'their_device_id' = ?2
	`
	deleteVerificationsQuery = `DELETE FROM verifications WHERE transaction_id = ?1`
)

var _ verificationhelper.VerificationStore = (*SQLiteVerificationStore)(nil)

func NewSQLiteVerificationStore(ctx context.Context, db *sql.DB) (*SQLiteVerificationStore, error) {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE verifications (
			transaction_id   TEXT  PRIMARY KEY NOT NULL,
			transaction_data JSONB NOT NULL
		);
		CREATE INDEX verifications_user_device_id ON
			verifications(transaction_data->>'their_user_id', transaction_data->>'their_device_id');
	`)
	return &SQLiteVerificationStore{db}, err
}

func (s *SQLiteVerificationStore) GetAllVerificationTransactions(ctx context.Context) ([]verificationhelper.VerificationTransaction, error) {
	rows, err := s.db.QueryContext(ctx, selectVerifications)
	return dbutil.NewRowIterWithError(rows, func(dbutil.Scannable) (txn verificationhelper.VerificationTransaction, err error) {
		err = rows.Scan(&dbutil.JSON{Data: &txn})
		return
	}, err).AsList()
}

func (vq *SQLiteVerificationStore) GetVerificationTransaction(ctx context.Context, txnID id.VerificationTransactionID) (txn verificationhelper.VerificationTransaction, err error) {
	zerolog.Ctx(ctx).Warn().Stringer("transaction_id", txnID).Msg("Getting verification transaction")
	row := vq.db.QueryRowContext(ctx, getVerificationByTransactionID, txnID)
	err = row.Scan(&dbutil.JSON{Data: &txn})
	if errors.Is(err, sql.ErrNoRows) {
		err = verificationhelper.ErrUnknownVerificationTransaction
	}
	return
}

func (vq *SQLiteVerificationStore) FindVerificationTransactionForUserDevice(ctx context.Context, userID id.UserID, deviceID id.DeviceID) (txn verificationhelper.VerificationTransaction, err error) {
	row := vq.db.QueryRowContext(ctx, getVerificationByUserDeviceID, userID, deviceID)
	err = row.Scan(&dbutil.JSON{Data: &txn})
	if errors.Is(err, sql.ErrNoRows) {
		err = verificationhelper.ErrUnknownVerificationTransaction
	}
	return
}

func (vq *SQLiteVerificationStore) SaveVerificationTransaction(ctx context.Context, txn verificationhelper.VerificationTransaction) (err error) {
	zerolog.Ctx(ctx).Debug().Any("transaction", &txn).Msg("Saving verification transaction")
	_, err = vq.db.ExecContext(ctx, `
		INSERT INTO verifications (transaction_id, transaction_data)
		VALUES (?1, ?2)
		ON CONFLICT (transaction_id) DO UPDATE
			SET transaction_data=excluded.transaction_data
	`, txn.TransactionID, &dbutil.JSON{Data: &txn})
	return
}

func (vq *SQLiteVerificationStore) DeleteVerification(ctx context.Context, txnID id.VerificationTransactionID) (err error) {
	_, err = vq.db.ExecContext(ctx, deleteVerificationsQuery, txnID)
	return
}
