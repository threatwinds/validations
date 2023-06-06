package validations

import (
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
)

func ValidateHexadecimal(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "value is not string: %v", value)
	}

	v = strings.ToLower(v)

	h, err := hex.DecodeString(v)
	if err != nil {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", err.Error())
	}

	hstr := hex.EncodeToString(h)

	return hstr, GenerateSHA3256(hstr), nil
}
