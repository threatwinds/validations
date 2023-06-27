package validations

import (
	"fmt"
)

func ValidateBoolean(value interface{}) (bool, string, error) {
	v, ok := value.(bool)
	if !ok {
		return false, "", fmt.Errorf("value is not boolean: %v", value)
	}

	return v, GenerateSHA3256(fmt.Sprint(v)), nil
}
