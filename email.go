package validations

import (
	"net/http"
	"net/mail"
	"strings"

	"github.com/quantfall/rerror"
)

func ValidateEmail(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "value is not string: %v", value)
	}

	addr, err := mail.ParseAddress(strings.ToLower(v))
	if err != nil {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", err.Error())
	}

	return addr.Address, GenerateSHA3256(addr.Address), nil
}
