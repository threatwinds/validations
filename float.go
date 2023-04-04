package validations

import (
	"fmt"
	"net/http"
	"reflect"

	"github.com/quantfall/rerror"
	"google.golang.org/grpc/codes"
)

func ValidateFloat(value interface{}) (float64, string, *rerror.Error) {
	t := reflect.TypeOf(value)
	if t.Kind() == reflect.Int64{
		value = float64(value.(int64))
	}
	v, ok := value.(float64)
	if !ok {
		return 0, "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "value is not float: %v", value)
	}

	return v, GenerateSHA3256(fmt.Sprint(v)), nil
}
