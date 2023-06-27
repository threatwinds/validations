package validations

import (
	"fmt"
	"strings"
)

func ValidateString(value interface{}, insensitive bool) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}

	if v == "" {
		return "", "", fmt.Errorf("value cannot be empty")
	}

	if insensitive {
		return strings.ToLower(v), GenerateSHA3256(strings.ToLower(v)), nil
	}

	return v, GenerateSHA3256(v), nil
}
