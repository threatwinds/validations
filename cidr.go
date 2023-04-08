package validations

import (
	"net"
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
)

func ValidateCIDR(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, "value is not string: %v", value)
	}
	ip, cidr, err := net.ParseCIDR(strings.ToLower(v))
	if err != nil {
		return "", "", rerror.ErrorF(http.StatusBadRequest, err.Error())
	}

	_, _, e := ValidateIP(ip.String())
	if e != nil {
		return "", "", e
	}

	cstr := cidr.String()
	return cstr, GenerateSHA3256(cstr), nil
}
