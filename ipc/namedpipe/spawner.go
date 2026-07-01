// Copyright (C) 2026 AsciiMoth

//go:build windows

package namedpipe

import "github.com/asciimoth/gonnect"

func spawnWorker(spawner gonnect.Spawner, worker func(), name string) {
	if spawner == nil {
		go worker()
		return
	}
	if _, err := spawner.Spawn(worker, name); err != nil {
		go worker()
	}
}
