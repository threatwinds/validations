package validations

import (
	"encoding/base64"
	"net/http"

	"github.com/quantfall/rerror"
)

func ValidateBase64(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "value is not string: %v", value)
	}
	_, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", err.Error())
	}

	return v, GenerateSHA3256(v), nil
}
