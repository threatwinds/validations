package validations

import (
	"fmt"
	"strings"
)

func ValidateSHA1(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}

	v = strings.ToLower(v)
	e := ValidateRegEx(`^[0-9a-f]{40}$`, v)
	if e != nil {
		return "", "", e
	}

	return v, GenerateSHA3256(v), nil
}
