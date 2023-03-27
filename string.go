package validations

import (
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
	"google.golang.org/grpc/codes"
)

func ValidateString(value interface{}, insensitive bool) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "value is not string: %v", value)
	}

	if v == "" {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "value cannot be empty")
	}

	if insensitive {
		return strings.ToLower(v), GenerateSHA3256(strings.ToLower(v)), nil
	}

	return v, GenerateSHA3256(v), nil
}
