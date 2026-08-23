package amnezia

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Uint32Range is the provider-neutral representation of AWG range values.
// Set=false means the parameter was omitted/off; Min==Max is a fixed value.
type Uint32Range struct {
	Min uint32
	Max uint32
	Set bool
}

func ParseUint32Range(value string) (Uint32Range, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "off") || strings.EqualFold(value, "(off)") {
		return Uint32Range{}, nil
	}
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return Uint32Range{}, errors.New("range must be a or a-b")
	}
	min, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil {
		return Uint32Range{}, err
	}
	max := min
	if len(parts) == 2 {
		max, err = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil {
			return Uint32Range{}, err
		}
	}
	if max < min {
		return Uint32Range{}, errors.New("range maximum is less than minimum")
	}
	return Uint32Range{Min: uint32(min), Max: uint32(max), Set: true}, nil
}

func (r Uint32Range) String() string {
	if !r.Set {
		return ""
	}
	if r.Min == r.Max {
		return strconv.FormatUint(uint64(r.Min), 10)
	}
	return fmt.Sprintf("%d-%d", r.Min, r.Max)
}

// Validate checks the ordering of a set range. An omitted range is valid.
func (r Uint32Range) Validate() error {
	if r.Set && r.Max < r.Min {
		return errors.New("range maximum is less than minimum")
	}
	return nil
}

// Toggle retains whether an AWG on/off field was explicitly present.
type Toggle struct {
	Enabled bool
	Set     bool
}

func parseToggle(value string) Toggle {
	value = strings.TrimSpace(value)
	if value == "" {
		return Toggle{}
	}
	return Toggle{Set: true, Enabled: !strings.EqualFold(value, "off") && !strings.EqualFold(value, "false") && value != "0"}
}

func (t Toggle) String() string {
	if !t.Set {
		return ""
	}
	if t.Enabled {
		return "on"
	}
	return "off"
}
