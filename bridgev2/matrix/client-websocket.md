# Login WebSocket byte tunnels

Provisioning clients advertise `client_websocket=2` when starting a login. The
connector receives an optional `LoginStartParams.WebSocketHTTP` transport, which
can be passed to its WebSocket library through an ordinary `http.Client`.
Version 2 is intentionally incompatible with the earlier long-poll prototype;
clients and bridges that don't recognize it keep their normal login path.

An outgoing WebSocket upgrade creates a `client_http` step with a `stream_id`.
The SDK opens the remote HTTPS connection, retains the raw upgraded response
body, and opens a second WebSocket to:

```
GET /v3/login/streams/{loginProcessID}/{streamID}
```

This endpoint uses normal provisioning authentication and requires the login's
owner. Each stream accepts only one tunnel attachment. The SDK wraps the tunnel
in `websocket.NetConn` with binary messages and copies bytes between it and the
remote upgraded connection in both directions. It starts copying **before**
submitting the remote 101 status, headers and stream ID through the existing
client HTTP response endpoint. That submission may wait until the connector
has exchanged enough data to produce a QR or another user-facing step.

The framework returns its side of the tunnel as the upgraded HTTP response's
`io.ReadWriteCloser`. The connector's existing WebSocket implementation still
owns remote framing, compression, control messages and network encryption.
The tunnel itself doesn't interpret messages or preserve their boundaries.

There are no polling endpoints, sequence numbers, acknowledgements, replay
queues or transparent reconnects. EOF/error closes the stream. The SDK must
close both connections when either copy ends. Loss of the tunnel fails that
connection rather than attempting to resume it.

The tunnel lives across login-step transitions, not across completed logins.
Cancellation, completion and the login's 30-minute deadline close its streams.
An upgrade that isn't completed within a minute also closes. At most eight
streams are allocated per login, with spent IDs retained until login removal
to prevent reattachment. Clients must restrict remote destinations and keep
their own stream copies bounded.

The gateway must forward WebSocket upgrades, including `Hijack` through response
writer wrappers. An HTTP request/response serialization path cannot carry this
tunnel without additional routing support.
