package validations

import (
	"net/http"

	"github.com/quantfall/rerror"
	"google.golang.org/grpc/codes"
)

func ValidatePhone(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "value is not string: %v", value)
	}

	e := ValidateRegEx(`^([+][1-9]{1,1}[0-9]{0,2})([\s]?[(][1-9]{1,1}[0-9]{0,3}[)])?([\s]?[-]?[0-9]{1,4}){1,3}$`, v)
	if e != nil {
		return "", "", e
	}

	return v, GenerateSHA3256(v), nil
}
