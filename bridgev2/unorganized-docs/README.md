# Megabridge
Megabridge, also known as bridgev2 (final naming is subject to change), is a
new high-level framework for writing puppeting Matrix bridges with hopefully
minimal boilerplate code.

## General architecture
Megabridge is split into three components: network connectors, the central
bridge module, and Matrix connectors.

* Network connectors are responsible for connecting to the remote (non-Matrix)
  network and handling all the protocol-specific details.
* The central bridge module has most of the generic bridge logic, such as
  keeping track of portal mappings and handling messages.
* Matrix connectors are responsible for connecting to Matrix. Initially there
  will be two Matrix connectors: one for the standard setup that connects to
  a Matrix homeserver as an application service, and another for Beeper's local
  bridge system. However, in the future there could be a third connector which
  uses a single bot account and [MSC4144] instead of an appservice with ghost
  users.

  [MSC4144]: https://github.com/matrix-org/matrix-spec-proposals/pull/4144

The central bridge module defines interfaces that it uses to interact with the
connectors on both sides. Additionally, the connectors are allowed to directly
call interface methods on other side.

## Getting started with a new network connector
To create a new network connector, you need to implement the
`NetworkConnector`, `LoginProcess`, `NetworkAPI` and `RemoteEvent` interfaces.

* `NetworkConnector` is the main entry point to the remote network. It is
  responsible for general non-user-specific things, as well as creating
  `NetworkAPI`s and starting login flows.
* `LoginProcess` is a state machine for logging into the remote network.
* `NetworkAPI` is the remote network client for a single login. It is
  responsible for maintaining the connection to the remote network, receiving
  incoming events, sending outgoing events, and fetching information like
  chat/user metadata.
* `RemoteEvent` represents a single event from the remote network, such as a
  message or a reaction. When the NetworkAPI receives an event, it should create
  a `RemoteEvent` object and pass it to the bridge using `Bridge.QueueRemoteEvent`.

### Login
Logins are implemented by combining three types of steps:

* `user_input` asks the user to enter some information, such as a phone number,
  username, email, password, or 2FA code.
* `cookies` either asks the user to extract cookies from their browser, or opens
  a webview to do it automatically (depending on whether the login is being done
  via bridge commands or a more advanced client).
* `display_and_wait` displays a QR code or other data to the user and waits until
  the remote network accepts the login.

The general flow is:

1. Login handler (bridge command or client) calls `NetworkConnector.GetLoginFlows`
   to get available login flows, and asks the user to pick one (or alternatively
   automatically picks the first one if there's only one option).
2. Login handler calls `NetworkConnector.CreateLogin` with the chosen flow ID and
   the network connector returns a `LoginProcess` object that remembers the user
   and flow.
3. Login handler calls `LoginProcess.Start` to get the first step.
4. Login handler calls the appropriate functions (`Wait`, `SubmitUserInput` or
   `SubmitCookies`) based on the step data as many times as needed.
5. When the login is done, the login process creates the `UserLogin` object and
   returns a `complete` step.
