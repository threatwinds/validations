package validations

import (
	"fmt"
	"net/http"
	"reflect"

	"github.com/quantfall/rerror"
)

func ValidateInteger(value interface{}) (int64, string, *rerror.Error) {
	t := reflect.TypeOf(value)
	if t.Kind() == reflect.Float64 {
		value = int64(value.(float64))
	}
	v, ok := value.(int64)
	if !ok {
		return 0, "", rerror.ErrorF(http.StatusBadRequest, "value is not integer: %v", value)
	}

	return int64(v), GenerateSHA3256(fmt.Sprint(int(v))), nil
}
