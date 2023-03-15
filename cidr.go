package validations

import (
	"net"
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
	"google.golang.org/grpc/codes"
)

func ValidateCIDR(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "value is not string: %v", value)
	}
	_, cidr, err := net.ParseCIDR(strings.ToLower(v))
	if err != nil {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, err.Error())
	}

	cstr := cidr.String()
	return cstr, GenerateSHA3256(cstr), nil
}
