package validations

import (
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
	"golang.org/x/crypto/sha3"
)

func ValidateSHA3256(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, "value is not string: %v", value)
	}
	v = strings.ToLower(v)
	e := ValidateRegEx(`^[0-9a-f]{64}$`, v)
	if e != nil {
		return "", "", e
	}

	return v, GenerateSHA3256(v), nil
}

func GenerateSHA3256(value string) string {
	sum := sha3.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
