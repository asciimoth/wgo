//go:build !linux

package device

import (
	"github.com/asciimoth/wgo/conn"
	"github.com/asciimoth/wgo/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
