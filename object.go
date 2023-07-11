package validations

import "fmt"

func ValidateObject(value interface{}) (string, string, error) {
	s1, h1, err := ValidateUUID(value)
	if err == nil {
		return s1.String(), h1, nil
	}
	s2, h2, err := ValidateMD5(value)
	if err == nil {
		return s2, h2, nil
	}
	s3, h3, err := ValidateSHA3256(value)
	if err == nil {
		return s3, h3, nil
	}

	return "", "", fmt.Errorf("invalid object: %v", value)
}
