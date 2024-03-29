package validations

import (
	"fmt"
	"strings"
)

// ValidateString validates a string value and returns the original value, its SHA3-256 hash and an error.
// If the insensitive flag is set to true, the value is converted to lowercase before hashing.
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
