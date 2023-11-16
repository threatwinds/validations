package validations

import "fmt"

// ValidateObject validates an object by checking if it's a valid UUID, MD5 or SHA3256 hash.
// If the object is valid, it returns the string representation of the hash, the hash itself and no error.
// If the object is invalid, it returns empty strings and an error.
func ValidateObject(value interface{}) (string, string, error) {
	s2, h2, err := ValidateMD5(value)
	if err == nil {
		return s2, h2, nil
	}
	s3, h3, err := ValidateSHA3256(value)
	if err == nil {
		return s3, h3, nil
	}
	s1, h1, err := ValidateUUID(value)
	if err == nil {
		return s1.String(), h1, nil
	}

	return "", "", fmt.Errorf("invalid object: %v", value)
}
