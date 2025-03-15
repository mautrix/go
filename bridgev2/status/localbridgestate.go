package status

type LocalBridgeAccountState string

const (
	// LocalBridgeAccountStateSetup means the user wants this account to be setup and connected
	LocalBridgeAccountStateSetup LocalBridgeAccountState = "SETUP"
	// LocalBridgeAccountStateDeleted means the user wants this account to be deleted
	LocalBridgeAccountStateDeleted LocalBridgeAccountState = "DELETED"
)

type LocalBridgeDeviceState string

const (
	// LocalBridgeDeviceStateSetup means this device is setup to be connected to this account
	LocalBridgeDeviceStateSetup LocalBridgeDeviceState = "SETUP"
	// LocalBridgeDeviceStateLoggedOut means the user has logged this particular device out while wanting their other devices to remain setup
	LocalBridgeDeviceStateLoggedOut LocalBridgeDeviceState = "LOGGED_OUT"
	// LocalBridgeDeviceStateError means this particular device has fallen into a persistent error state that may need user intervention to fix
	LocalBridgeDeviceStateError LocalBridgeDeviceState = "ERROR"
	// LocalBridgeDeviceStateDeleted means this particular device has cleaned up after the account as a whole was requested to be deleted
	LocalBridgeDeviceStateDeleted LocalBridgeDeviceState = "DELETED"
)
