package validations

import (
	"net/http"

	"github.com/quantfall/rerror"
	"google.golang.org/grpc/codes"
)

func ValidateKeyValue(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "value is not string: %v", value)
	}

	e := ValidateRegEx(`^(?i)(.+)([|])(.+)$`, v)
	if e != nil {
		return "", "", e
	}

	return v, GenerateSHA3256(v), nil
}
