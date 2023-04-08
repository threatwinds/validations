package validations

import (
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
)

func ValidateMD5(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, "value is not string: %v", value)
	}

	v = strings.ToLower(v)

	if len([]rune(v)) == 32 {
		e := ValidateRegEx(`^[0-9a-f]{32}$`, v)
		if e != nil {
			return "", "", e
		}
	} else {
		e := ValidateRegEx(`^[0-9a-f]{16}$`, v)
		if e != nil {
			return "", "", e
		}
	}

	return v, GenerateSHA3256(v), nil
}
