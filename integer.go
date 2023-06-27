package validations

import (
	"fmt"
	"reflect"
)

func ValidateInteger(value interface{}) (int64, string, error) {
	t := reflect.TypeOf(value)
	if t.Kind() == reflect.Float64 {
		value = int64(value.(float64))
	}
	v, ok := value.(int64)
	if !ok {
		return 0, "", fmt.Errorf("value is not integer: %v", value)
	}

	return int64(v), GenerateSHA3256(fmt.Sprint(int(v))), nil
}
