package validations

import (
	"fmt"
	"net"
	"strings"
)

func ValidateCIDR(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}
	ip, cidr, err := net.ParseCIDR(strings.ToLower(v))
	if err != nil {
		return "", "", err
	}

	_, _, e := ValidateIP(ip.String())
	if e != nil {
		return "", "", e
	}

	cstr := cidr.String()
	return cstr, GenerateSHA3256(cstr), nil
}
