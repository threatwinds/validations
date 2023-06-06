package validations

import (
	"net"
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
)

func ValidateIP(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "value not string: %v", value)
	}

	addr := net.ParseIP(strings.ToLower(v))
	if addr == nil {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "invalid IP: %s", v)
	}
	if addr.IsPrivate() {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "cannot accept private IP: %s", v)
	}
	if addr.IsInterfaceLocalMulticast() {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "cannot accept interface local multicast IP: %s", v)
	}
	if addr.IsLinkLocalMulticast() {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "cannot accept link local multicast IP: %s", v)
	}
	if addr.IsLinkLocalUnicast() {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "cannot accept link local unicast IP: %s", v)
	}
	if addr.IsLoopback() {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "cannot accept loopback IP: %s", v)
	}
	if addr.IsMulticast() {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "cannot accept multicast IP: %s", v)
	}
	if addr.IsUnspecified() {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "cannot accept unspecified IP: %s", v)
	}

	a := addr.String()

	return a, GenerateSHA3256(a), nil
}
