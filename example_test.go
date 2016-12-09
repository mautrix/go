package gomatrix

import (
	"fmt"
)

func Example() {
	cli, _ := NewClient("https://matrix.org", "@example:matrix.org", "MDAefhiuwehfuiwe")
	syncer := cli.Syncer.(*DefaultSyncer)
	syncer.OnEventType("m.room.message", func(ev *Event) {
		fmt.Println("Message: ", ev)
	})
	// To make the example non-blocking, call Sync() in a goroutine.
	if err := cli.Sync(); err != nil {
		fmt.Println("Sync() returned ", err)
	}
}
