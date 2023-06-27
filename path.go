package validations

import (
	"fmt"
	"strings"
)

func ValidatePath(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}

	v = strings.ToLower(v)

	if strings.Contains(v, "://") {
		return "", "", fmt.Errorf("value is not valid path: %v", value)
	}

	return v, GenerateSHA3256(v), nil
}
