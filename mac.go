package validations

import (
	"fmt"
	"strings"
)

func ValidateMAC(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}

	v = strings.ToUpper(v)

	e := ValidateRegEx(`^([0-9A-F]{2,2}[-]){5,5}([0-9A-F]{2,2})$`, v)
	if e != nil {
		return "", "", e
	}

	return v, GenerateSHA3256(v), nil
}
