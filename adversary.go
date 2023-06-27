package validations

import (
	"fmt"
)

func ValidateAdversary(value interface{}) (string, string, error) {
	_, _, e1 := ValidateURL(value)

	_, _, e3 := ValidateUUID(value)

	_, _, e4 := ValidateEmail(value)

	_, _, e5 := ValidateIP(value)

	_, _, e6 := ValidatePhone(value)

	_, _, e7 := ValidateFQDN(value)

	if e1 == nil || e3 == nil || e4 == nil || e5 == nil || e6 == nil || e7 == nil {
		return "", "", fmt.Errorf("invalid adversary: %v", value)
	}

	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}

	return v, GenerateSHA3256(v), nil
}
