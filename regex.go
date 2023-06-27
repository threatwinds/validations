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
