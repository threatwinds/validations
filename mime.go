package validations

import (
	"fmt"
	"strings"
)

func ValidateMime(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}

	v = strings.ToLower(v)

	e := ValidateRegEx(`^([a-z]+)[/]([a-z0-9]+[a-z0-9+-.][a-z0-9]+)+$`, v)
	if e != nil {
		return "", "", e
	}

	return v, GenerateSHA3256(v), nil
}
