package validations

import (
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
)

func ValidateMAC(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, "value is not string: %v", value)
	}

	v = strings.ToUpper(v)

	e := ValidateRegEx(`^([0-9A-F]{2,2}[-]){5,5}([0-9A-F]{2,2})$`, v)
	if e != nil {
		return "", "", e
	}

	return v, GenerateSHA3256(v), nil
}
