package validations

import "fmt"

func ValidateObject(value interface{}) (string, string, error) {
	s1, h1, e1 := ValidateUUID(value)
	if e1 == nil {
		return s1.String(), h1, nil
	}
	s2, h2, e2 := ValidateMD5(value)
	if e2 == nil {
		return s2, h2, nil
	}
	s3, h3, e3 := ValidateSHA3256(value)
	if e3 == nil {
		return s3, h3, nil
	}

	return "", "", fmt.Errorf("invalid object: %v", value)
}
