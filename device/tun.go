/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"

	gtun "github.com/asciimoth/gonnect/tun"
)

const DefaultMTU = 1420

func (device *Device) RoutineTUNEventReader(tun *tunState) {
	defer func() {
		device.log.Debugf("Routine: event worker - stopped")
		tun.wg.Done()
		device.state.stopping.Done()
	}()

	device.log.Debugf("Routine: event worker - started")

	for event := range tun.device.Events() {
		if event&gtun.EventMTUUpdate != 0 {
			mtu, err := tun.device.MTU()
			if err != nil {
				device.log.Errf("Failed to load updated MTU of device: %v", err)
				continue
			}
			if mtu < 0 {
				device.log.Errf("MTU not updated to negative value: %v", mtu)
				continue
			}
			var tooLarge string
			if mtu > MaxContentSize {
				tooLarge = fmt.Sprintf(" (too large, capped at %v)", MaxContentSize)
				mtu = MaxContentSize
			}
			old := device.tun.mtu.Swap(int32(mtu))
			if int(old) != mtu {
				device.log.Debugf("MTU updated: %v%s", mtu, tooLarge)
			}
		}

		if event&gtun.EventUp != 0 {
			device.log.Debugf("Interface up requested")
			device.Up()
		}

		if event&gtun.EventDown != 0 {
			device.log.Debugf("Interface down requested")
			device.Down()
		}
	}
}
