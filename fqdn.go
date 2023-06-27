package validations

import (
	"fmt"
	"strings"
)

func ValidateFQDN(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}

	v = strings.ToLower(v)

	e := ValidateRegEx(`^(?i)[a-z0-9]+(([-]{1,2}[a-z0-9]+)*([\.]{1}[a-z0-9]+)*)*(\.[a-z]{2,20})$`, v)
	if e != nil {
		return "", "", e
	}

	return v, GenerateSHA3256(v), nil
}
