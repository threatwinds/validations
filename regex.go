package validations

import (
	"fmt"
	"regexp"
)

func ValidateRegEx(regex, value string) error {
	expression := regexp.MustCompile(regex)
	matches := expression.FindAllString(value, -1)
	if len(matches) != 1 {
		return fmt.Errorf("value '%s' does not match with regexp '%s'", value, regex)
	}

	if matches[0] != value {
		return fmt.Errorf("value '%s' does not match with regexp '%s'", value, regex)
	}

	return nil
}

func ValidateRegexComp(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}

	_, err := regexp.Compile(v)
	if err != nil {
		return "", "", err
	}

	return v, GenerateSHA3256(v), nil
}
