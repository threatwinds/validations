package validations

import (
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"google.golang.org/grpc/codes"
)

func ValidateCity(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "value is not string: %v", value)
	}

	v = cases.Title(language.English).String(strings.ToLower(v))

	return v, GenerateSHA3256(v), nil
}
