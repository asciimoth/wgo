/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 AsciiMoth
 */

package device

import "github.com/asciimoth/gonnect"

// spawnWorker starts a long-lived device worker through spawner when one is
// provided. A nil spawner preserves the package's historical direct goroutine
// behavior.
func spawnWorker(spawner gonnect.Spawner, logger Logger, worker func(), name string) {
	if spawner == nil {
		go worker()
		return
	}
	if _, err := spawner.Spawn(worker, name); err != nil {
		loggerOrNop(logger).Errf("Failed to spawn %q: %v", name, err)
		go worker()
	}
}

func (device *Device) spawnWorker(worker func(), name string) {
	spawnWorker(device.spawner, device.log, worker, name)
}

func (device *Device) logWorkerLifecyclef(format string, args ...any) {
	if device.spawner != nil {
		return
	}
	device.log.Debugf(format, args...)
}
