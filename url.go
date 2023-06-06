package validations

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/quantfall/rerror"
)

func ValidateURL(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "value is not string: %v", value)
	}

	tmp, err := url.ParseRequestURI(v)
	if err != nil {
		return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", err.Error())
	}
	tmp.Host = strings.ToLower(tmp.Host)
	tmp.Scheme = strings.ToLower(tmp.Scheme)

	surl := tmp.String()
	return surl, GenerateSHA3256(surl), nil
}
