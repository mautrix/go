// Copyright (C) 2017 Tulir Asokan
// Copyright (C) 2018-2020 Luca Weiss
// Copyright (C) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/chzyer/readline"
	_ "github.com/mattn/go-sqlite3"
	"maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var homeserver = flag.String("homeserver", "", "Matrix homeserver")
var username = flag.String("username", "", "Matrix username localpart")
var password = flag.String("password", "", "Matrix password")
var database = flag.String("database", "mautrix-example.db", "SQLite database path")

func main() {
	flag.Parse()
	if *username == "" || *password == "" || *homeserver == "" {
		_, _ = fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	client, err := mautrix.NewClient(*homeserver, "", "")
	if err != nil {
		panic(err)
	}
	rl, err := readline.New("[no room]> ")
	if err != nil {
		panic(err)
	}
	defer rl.Close()
	stdout := rl.Stdout()
	client.Logger = maulogger.DefaultLogger
	// Don't log to stdout, it messes up the readline :(
	maulogger.DefaultLogger.PrintLevel = maulogger.LevelFatal.Severity
	err = maulogger.OpenFile()
	if err != nil {
		panic(err)
	}

	var lastRoomID id.RoomID

	syncer := client.Syncer.(*mautrix.DefaultSyncer)
	syncer.OnEventType(event.EventMessage, func(source mautrix.EventSource, evt *event.Event) {
		lastRoomID = evt.RoomID
		rl.SetPrompt(fmt.Sprintf("%s> ", lastRoomID))
		_, _ = fmt.Fprintf(stdout, "<%[1]s> %[4]s (%[2]s/%[3]s)\n", evt.Sender, evt.Type.String(), evt.ID, evt.Content.AsMessage().Body)
	})

	cryptoHelper, err := cryptohelper.NewCryptoHelper(client, []byte("meow"), *database)
	if err != nil {
		panic(err)
	}

	// You can also store the user/device IDs and access token and put them in the client beforehand instead of using LoginAs.
	//client.UserID = "..."
	//client.DeviceID = "..."
	//client.AccessToken = "..."
	// You don't need to set a device ID in LoginAs because the crypto helper will set it for you if necessary.
	cryptoHelper.LoginAs = &mautrix.ReqLogin{
		Type:       mautrix.AuthTypePassword,
		Identifier: mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: *username},
		Password:   *password,
	}
	// If you want to use multiple clients with the same DB, you should set a distinct database account ID for each one.
	//cryptoHelper.DBAccountID = ""
	err = cryptoHelper.Init()
	if err != nil {
		panic(err)
	}
	// Set the client crypto helper in order to automatically encrypt outgoing messages
	client.Crypto = cryptoHelper

	_, _ = fmt.Fprintln(stdout, "Now running")
	syncCtx, cancelSync := context.WithCancel(context.Background())
	var syncStopWait sync.WaitGroup
	syncStopWait.Add(1)

	go func() {
		err = client.SyncWithContext(syncCtx)
		defer syncStopWait.Done()
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	for {
		line, err := rl.Readline()
		if err != nil { // io.EOF
			break
		}
		if lastRoomID == "" {
			_, _ = fmt.Fprintln(stdout, "Wait for an incoming message before sending messages")
			continue
		}
		resp, err := client.SendText(lastRoomID, line)
		if err != nil {
			_, _ = fmt.Fprintln(stdout, "Failed to send:", err)
		} else {
			_, _ = fmt.Fprintln(stdout, "Sent", resp.EventID)
		}
	}
	cancelSync()
	syncStopWait.Wait()
	err = cryptoHelper.Close()
	if err != nil {
		_, _ = fmt.Fprintln(stdout, "Error closing db:", err)
	}
}
