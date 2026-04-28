//go:build !linux

package device

import (
	conn "github.com/asciimoth/batchudp"
	"github.com/asciimoth/wgo/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
