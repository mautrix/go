package gomatrix

import (
	"fmt"
)

func Example_sync() {
	cli, _ := NewClient("https://matrix.org", "@example:matrix.org", "MDAefhiuwehfuiwe")
	syncer := cli.Syncer.(*DefaultSyncer)
	syncer.OnEventType("m.room.message", func(ev *Event) {
		fmt.Println("Message: ", ev)
	})

	// Blocking version
	if err := cli.Sync(); err != nil {
		fmt.Println("Sync() returned ", err)
	}

	// Non-blocking version
	go func() {
		for {
			if err := cli.Sync(); err != nil {
				fmt.Println("Sync() returned ", err)
			}
			// Optional: Wait a period of time before trying to sync again.
		}
	}()
}
