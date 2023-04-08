package validations

import (
	"encoding/base64"
	"net/http"

	"github.com/quantfall/rerror"
)

func ValidateBase64(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, "value is not string: %v", value)
	}
	_, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return "", "", rerror.ErrorF(http.StatusBadRequest, err.Error())
	}

	return v, GenerateSHA3256(v), nil
}
