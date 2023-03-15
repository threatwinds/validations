package validations

import (
	"net"
	"net/http"
	"strings"

	"github.com/quantfall/rerror"
	"google.golang.org/grpc/codes"
)

func ValidateIP(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "value not string: %v", value)
	}

	addr := net.ParseIP(strings.ToLower(v))
	if addr == nil {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "invalid IP: %s", v)
	}
	if addr.IsPrivate() {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "cannot accept private IP: %s", v)
	}
	if addr.IsInterfaceLocalMulticast() {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "cannot accept interface local multicast IP: %s", v)
	}
	if addr.IsLinkLocalMulticast() {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "cannot accept link local multicast IP: %s", v)
	}
	if addr.IsLinkLocalUnicast() {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "cannot accept link local unicast IP: %s", v)
	}
	if addr.IsLoopback() {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "cannot accept loopback IP: %s", v)
	}
	if addr.IsMulticast() {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "cannot accept multicast IP: %s", v)
	}
	if addr.IsUnspecified() {
		return "", "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "cannot accept unspecified IP: %s", v)
	}

	a := addr.String()

	return a, GenerateSHA3256(a), nil
}
