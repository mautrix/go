# goolm

[![Please don't upload to GitHub](https://nogithub.codeberg.page/badge.svg)](https://nogithub.codeberg.page)
[![GoDoc](https://godoc.org/codeberg.org/DerLukas/goolm?status.svg)](https://godoc.org/codeberg.org/DerLukas/goolm)

### A Go implementation of Olm and Megolm

goolm is a pure Go implementation of libolm. Libolm is a cryptographic library used for end-to-end encryption in Matrix and wirtten in C++.
With goolm there is no need to use cgo when building Matrix clients in go.

See the GoDoc for usage.

This package is written to be a easily used in github.com/mautrix/go/crypto/olm.

PR's are always welcome.

# Features

* Test files for most methods and functions adapted from libolm

## Supported
* [Olm](https://matrix-org.github.io/vodozemac/vodozemac/olm/index.html)
* Pickle structs with encryption using JSON marshalling
* Pickle structs with encryption using the libolm format
* [Megolm](https://matrix-org.github.io/vodozemac/vodozemac/megolm/index.html)
* Inbound and outbound group sessions
* [SAS](https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing) support

# License

MIT licensed. See the LICENSE file for details.
