/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package ipc

import "github.com/asciimoth/gonnect"

// spawnWorker starts long-lived IPC workers through spawner when one is
// provided. A nil spawner preserves direct goroutine spawning.
func spawnWorker(spawner gonnect.Spawner, worker func(), name string) {
	if spawner == nil {
		go worker()
		return
	}
	if _, err := spawner.Spawn(worker, name); err != nil {
		go worker()
	}
}
