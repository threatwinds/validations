package validations

import (
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
	"google.golang.org/grpc/codes"
)

func ValidateHostOrDomain(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "value is not string: %v", value)
	}

	v = strings.ToLower(v)

	e := ValidateRegEx(`^(?i)[a-z0-9]+(([-]{1,2}[a-z0-9]+)*([\.]{1}[a-z0-9]+)*)*(\.[a-z]{2,20})$`, v)
	if e != nil {
		return "", "", e
	}

	return v, GenerateSHA3256(v), nil
}