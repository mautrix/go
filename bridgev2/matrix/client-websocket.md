# Client WebSockets during login

Provisioning clients can advertise `client_websocket=1` when starting a login.
Connectors implementing `LoginProcessWithParams` then receive an optional
`LoginStartParams.WebSocketHTTP` transport. It can be installed in an HTTP client
used by a WebSocket library that accepts upgraded `io.ReadWriteCloser` bodies.
The existing `client_http=1` capability is independent and unchanged.

The connector keeps ownership of the WebSocket protocol, encryption, login
state, and reconnection. The provisioning client opens the remote HTTPS
connection and relays raw bytes. It must not add another layer of WebSocket
framing. Streams exist only for the lifetime of the login.

## Upgrade

A WebSocket HTTP GET produces a normal `client_http` login step with an additional
`stream_id`. The client forwards the handshake and returns its status and headers
through the existing client HTTP submission endpoint. On a successful 101
response, it echoes `stream_id` and leaves `body` empty. Otherwise it returns an
ordinary HTTP response or error, without a stream ID.

The client must start the relay concurrently with submitting the handshake:
submission can wait for the next user-facing step, which may itself depend on
traffic over the stream. Stream workers must survive step transitions and must
not inherit the deadline of an individual provisioning request.

## Relay

Routes are relative to the provisioning prefix and require the same authenticated
user as the login:

* `GET /v3/login/streams/{loginProcessID}/{streamID}/poll` returns a
  `LoginClientStreamPacket`. It waits up to 20 seconds. An empty packet with
  sequence zero is a heartbeat, not EOF.
* `POST /v3/login/streams/{loginProcessID}/{streamID}/exchange` accepts a
  `LoginClientStreamExchange` and returns `LoginClientStreamExchangeResponse`.

Both directions use independent sequences starting at one. Packets contain up to
64 KiB of raw bytes (base64 in JSON). A terminal packet has `closed: true`, with
an optional bounded error. Sequence zero is not valid for submitted packets.

The client writes polled bytes to the remote connection in order, then sends
`ack` in an exchange. Polls repeat the same unacknowledged packet. A duplicate
packet is acknowledged without writing it twice. A sequence gap is an error.
The bridge's `Write` returns success only after this acknowledgement.

Remote bytes are submitted in the exchange's `packet` field. Its response's
`ack` is the last accepted client-to-bridge sequence. Retry the same packet when
an HTTP response is lost. Only one data submission may be outstanding per
stream, but acknowledgement-only exchanges must remain independent: otherwise
backpressure on reads could deadlock writes. Accepted data is buffered with a
256 KiB limit; a full buffer backpressures further submissions.

HTTP retries do not reopen the remote connection. A failed socket write,
unrecoverable relay error or sequence gap terminates the stream rather than
replaying ambiguous bytes onto another socket. A terminal poll packet overrides
outstanding data and must close the client connection even if its sequence skips
an unacknowledged packet. Closing a failed stream never acknowledges that data.

## Lifetime and limits

Login cancellation, completion or timeout closes every stream. An idle stream
also closes after a minute without poll/exchange activity. Closed stream records
remain available for retries until the login is removed. At most eight streams
can be allocated per login, including closed records.

Clients must bound their own buffers and relay request deadlines, close sockets
on SDK shutdown/cancellation, restrict destination URLs, and avoid logging raw
payloads or authentication headers. A login-complete response is not permission
to retain a device-relayed connection for normal messaging.
