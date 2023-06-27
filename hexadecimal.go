package validations

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func ValidateHexadecimal(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}

	v = strings.ToLower(v)

	h, err := hex.DecodeString(v)
	if err != nil {
		return "", "", err
	}

	hstr := hex.EncodeToString(h)

	return hstr, GenerateSHA3256(hstr), nil
}
