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

	if strings.Contains(v, "://"){
		return "", "", rerror.ErrorF(http.StatusBadRequest, "value is not valid path: %v", value)
	}

	return v, GenerateSHA3256(v), nil
}
