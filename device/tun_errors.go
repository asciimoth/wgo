// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 AsciiMoth

package device

import "errors"

const tooManySegmentsErrorMessage = "too many segments"

func isTooManySegmentsError(err error) bool {
	return isPlatformTooManySegmentsError(err) || hasErrorMessage(err, tooManySegmentsErrorMessage)
}

func hasErrorMessage(err error, want string) bool {
	for err != nil {
		if err.Error() == want {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}
