// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/chzyer/readline"
	_ "github.com/mattn/go-sqlite3"
	"go.mau.fi/util/dbutil"
	_ "go.mau.fi/util/dbutil/litestream"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exzerolog"
	"go.mau.fi/zeroconfig"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/hicli"
	"maunium.net/go/mautrix/id"
)

var writerTypeReadline zeroconfig.WriterType = "hitest_readline"

func main() {
	hicli.InitialDeviceDisplayName = "mautrix hitest"
	rl := exerrors.Must(readline.New("> "))
	defer func() {
		_ = rl.Close()
	}()
	zeroconfig.RegisterWriter(writerTypeReadline, func(config *zeroconfig.WriterConfig) (io.Writer, error) {
		return rl.Stdout(), nil
	})
	log := exerrors.Must((&zeroconfig.Config{
		Writers: []zeroconfig.WriterConfig{{
			Type:   writerTypeReadline,
			Format: zeroconfig.LogFormatPrettyColored,
		}},
	}).Compile())
	exzerolog.SetupDefaults(log)

	rawDB := exerrors.Must(dbutil.NewWithDialect("hicli.db", "sqlite3-fk-wal"))
	ctx := log.WithContext(context.Background())
	cli := hicli.New(rawDB, *log, []byte("meow"))
	userID, _ := cli.DB.Account.GetFirstUserID(ctx)
	exerrors.PanicIfNotNil(cli.Start(ctx, userID))
	if !cli.IsLoggedIn() {
		rl.SetPrompt("User ID: ")
		userID := id.UserID(exerrors.Must(rl.Readline()))
		_, serverName := exerrors.Must2(userID.Parse())
		discovery, err := mautrix.DiscoverClientAPI(ctx, serverName)
		if discovery == nil {
			log.Fatal().Err(err).Msg("Failed to discover homeserver")
		}
		password := exerrors.Must(rl.ReadPassword("Password: "))
		recoveryCode := exerrors.Must(rl.ReadPassword("Recovery code: "))
		exerrors.PanicIfNotNil(cli.LoginAndVerify(ctx, discovery.Homeserver.BaseURL, userID.String(), string(password), string(recoveryCode)))
	}
	rl.SetPrompt("> ")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
