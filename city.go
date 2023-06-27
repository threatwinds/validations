package validations

import (
	"fmt"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func ValidateCity(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}

	v = cases.Title(language.English).String(strings.ToLower(v))

	return v, GenerateSHA3256(v), nil
}
