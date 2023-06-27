package validations

import (
	"fmt"
	"reflect"
)

func ValidateFloat(value interface{}) (float64, string, error) {
	t := reflect.TypeOf(value)
	if t.Kind() == reflect.Int64 {
		value = float64(value.(int64))
	}
	v, ok := value.(float64)
	if !ok {
		return 0, "", fmt.Errorf("value is not float: %v", value)
	}

	return v, GenerateSHA3256(fmt.Sprint(v)), nil
}
