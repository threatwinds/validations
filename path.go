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
	
	_, _, e1 := ValidateURL(value)
	if e1 == nil {
		return "", "", rerror.ErrorF(http.StatusBadRequest, "invalid path: %v", v)
	}

	v = strings.ToLower(v)

	return v, GenerateSHA3256(v), nil
}
