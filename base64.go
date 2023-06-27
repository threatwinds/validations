package validations

import (
	"encoding/base64"
	"fmt"
)

func ValidateBase64(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}
	_, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return "", "", err
	}

	return v, GenerateSHA3256(v), nil
}
