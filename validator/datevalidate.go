package validator

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const maxTimeGap = 30 * time.Second // 30 secs

func newPublicError(msg string) *gin.Error {
	return &gin.Error{
		Err:  errors.New(msg),
		Type: gin.ErrorTypePublic,
	}
}

// ErrDateNotInRange error when date not in aceptable range
var ErrDateNotInRange = newPublicError("Date submit is not in aceptable range")

// DateValidator checking validate by time range
type DateValidator struct {
	// TimeGap is max time different between client submit timestamp
	// and server time that considered valid. The time precision is millisecond.
	TimeGap time.Duration
}

// NewDateValidator return DateValidator with default value (30 second)
func NewDateValidator() *DateValidator {
	return &DateValidator{
		TimeGap: maxTimeGap,
	}
}

// Validate return error when checking if header date is valid or not
func (v *DateValidator) Validate(r *http.Request) error {
	t, err := http.ParseTime(r.Header.Get("date"))
	if err != nil {
		return newPublicError(fmt.Sprintf("Could not parse date header. Error: %s", err.Error()))
	}
	serverTime := time.Now()
	start := serverTime.Add(-v.TimeGap)
	stop := serverTime.Add(v.TimeGap)
	if t.Before(start) || t.After(stop) {
		return ErrDateNotInRange
	}
	return nil
}
