package validations

import (
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
)

func ValidateSHA1(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, "value is not string: %v", value)
	}

	v = strings.ToLower(v)
	e := ValidateRegEx(`^[0-9a-f]{40}$`, v)
	if e != nil {
		return "", "", e
	}

	return v, GenerateSHA3256(v), nil
}
