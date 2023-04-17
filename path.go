package validations

import (
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
)

func ValidatePath(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, "value is not string: %v", value)
	}

	v = strings.ToLower(v)

	e1 := ValidateRegEx("^(?:[\\w]\\:)(\\[a-zA-Z_\\-\\s0-9.]+)+$", v)

	e2 := ValidateRegEx("^(/?[a-zA-Z_\\-\\s0-9.]+)+$", v)

	if e1 != nil && e2 != nil {
		return "", "", rerror.ErrorF(http.StatusBadRequest, "invalid path: %s", v)
	}

	return v, GenerateSHA3256(v), nil
}
