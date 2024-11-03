package verificationhelper

import (
	"context"
	"errors"
	"fmt"

	"go.mau.fi/util/jsontime"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var ErrUnknownVerificationTransaction = errors.New("unknown transaction ID")

type VerificationState int

const (
	VerificationStateRequested VerificationState = iota
	VerificationStateReady

	VerificationStateTheirQRScanned // We scanned their QR code
	VerificationStateOurQRScanned   // They scanned our QR code

	VerificationStateSASStarted       // An SAS verification has been started
	VerificationStateSASAccepted      // An SAS verification has been accepted
	VerificationStateSASKeysExchanged // An SAS verification has exchanged keys
	VerificationStateSASMACExchanged  // An SAS verification has exchanged MACs
)

func (step VerificationState) String() string {
	switch step {
	case VerificationStateRequested:
		return "requested"
	case VerificationStateReady:
		return "ready"
	case VerificationStateTheirQRScanned:
		return "their_qr_scanned"
	case VerificationStateOurQRScanned:
		return "our_qr_scanned"
	case VerificationStateSASStarted:
		return "sas_started"
	case VerificationStateSASAccepted:
		return "sas_accepted"
	case VerificationStateSASKeysExchanged:
		return "sas_keys_exchanged"
	case VerificationStateSASMACExchanged:
		return "sas_mac"
	default:
		return fmt.Sprintf("VerificationState(%d)", step)
	}
}

type VerificationTransaction struct {
	ExpirationTime jsontime.UnixMilli `json:"expiration_time,omitempty"`

	// RoomID is the room ID if the verification is happening in a room or
	// empty if it is a to-device verification.
	RoomID id.RoomID `json:"room_id,omitempty"`

	// VerificationState is the current step of the verification flow.
	VerificationState VerificationState `json:"verification_state"`
	// TransactionID is the ID of the verification transaction.
	TransactionID id.VerificationTransactionID `json:"transaction_id"`

	// TheirDeviceID is the device ID of the device that either made the
	// initial request or accepted our request.
	TheirDeviceID id.DeviceID `json:"their_device_id,omitempty"`
	// TheirUserID is the user ID of the other user.
	TheirUserID id.UserID `json:"their_user_id,omitempty"`
	// TheirSupportedMethods is a list of verification methods that the other
	// device supports.
	TheirSupportedMethods []event.VerificationMethod `json:"their_supported_methods,omitempty"`

	// SentToDeviceIDs is a list of devices which the initial request was sent
	// to. This is only used for to-device verification requests, and is meant
	// to be used to send cancellation requests to all other devices when a
	// verification request is accepted via a m.key.verification.ready event.
	SentToDeviceIDs []id.DeviceID `json:"sent_to_device_ids,omitempty"`

	// QRCodeSharedSecret is the shared secret that was encoded in the QR code
	// that we showed.
	QRCodeSharedSecret []byte `json:"qr_code_shared_secret,omitempty"`

	StartedByUs              bool                                 `json:"started_by_us,omitempty"`               // Whether the verification was started by us
	StartEventContent        *event.VerificationStartEventContent `json:"start_event_content,omitempty"`         // The m.key.verification.start event content
	Commitment               []byte                               `json:"committment,omitempty"`                 // The commitment from the m.key.verification.accept event
	MACMethod                event.MACMethod                      `json:"mac_method,omitempty"`                  // The method used to calculate the MAC
	EphemeralKey             *ECDHPrivateKey                      `json:"ephemeral_key,omitempty"`               // The ephemeral key
	EphemeralPublicKeyShared bool                                 `json:"ephemeral_public_key_shared,omitempty"` // Whether this device's ephemeral public key has been shared
	OtherPublicKey           *ECDHPublicKey                       `json:"other_public_key,omitempty"`            // The other device's ephemeral public key
	ReceivedTheirMAC         bool                                 `json:"received_their_mac,omitempty"`          // Whether we have received their MAC
	SentOurMAC               bool                                 `json:"sent_our_mac,omitempty"`                // Whether we have sent our MAC
	ReceivedTheirDone        bool                                 `json:"received_their_done,omitempty"`         // Whether we have received their done event
	SentOurDone              bool                                 `json:"sent_our_done,omitempty"`               // Whether we have sent our done event
}

type VerificationStore interface {
	// DeleteVerification deletes a verification transaction by ID
	DeleteVerification(ctx context.Context, txnID id.VerificationTransactionID) error
	// GetVerificationTransaction gets a verification transaction by ID
	GetVerificationTransaction(ctx context.Context, txnID id.VerificationTransactionID) (VerificationTransaction, error)
	// SaveVerificationTransaction saves a verification transaction by ID
	SaveVerificationTransaction(ctx context.Context, txn VerificationTransaction) error
	// FindVerificationTransactionForUserDevice finds a verification
	// transaction by user and device ID
	FindVerificationTransactionForUserDevice(ctx context.Context, userID id.UserID, deviceID id.DeviceID) (VerificationTransaction, error)
	// GetAllVerificationTransactions returns all of the verification
	// transactions. This is used to reset the cancellation timeouts.
	GetAllVerificationTransactions(ctx context.Context) ([]VerificationTransaction, error)
}

type InMemoryVerificationStore struct {
	txns map[id.VerificationTransactionID]VerificationTransaction
}

var _ VerificationStore = (*InMemoryVerificationStore)(nil)

func NewInMemoryVerificationStore() *InMemoryVerificationStore {
	return &InMemoryVerificationStore{
		txns: map[id.VerificationTransactionID]VerificationTransaction{},
	}
}

func (i *InMemoryVerificationStore) DeleteVerification(ctx context.Context, txnID id.VerificationTransactionID) error {
	if _, ok := i.txns[txnID]; !ok {
		return ErrUnknownVerificationTransaction
	}
	delete(i.txns, txnID)
	return nil
}

func (i *InMemoryVerificationStore) GetVerificationTransaction(ctx context.Context, txnID id.VerificationTransactionID) (VerificationTransaction, error) {
	if _, ok := i.txns[txnID]; !ok {
		return VerificationTransaction{}, ErrUnknownVerificationTransaction
	}
	return i.txns[txnID], nil
}

func (i *InMemoryVerificationStore) SaveVerificationTransaction(ctx context.Context, txn VerificationTransaction) error {
	i.txns[txn.TransactionID] = txn
	return nil
}

func (i *InMemoryVerificationStore) FindVerificationTransactionForUserDevice(ctx context.Context, userID id.UserID, deviceID id.DeviceID) (VerificationTransaction, error) {
	for _, existingTxn := range i.txns {
		if existingTxn.TheirUserID == userID && existingTxn.TheirDeviceID == deviceID {
			return existingTxn, nil
		}
	}
	return VerificationTransaction{}, ErrUnknownVerificationTransaction
}

func (i *InMemoryVerificationStore) GetAllVerificationTransactions(ctx context.Context) (txns []VerificationTransaction, err error) {
	for _, txn := range i.txns {
		txns = append(txns, txn)
	}
	return
}
