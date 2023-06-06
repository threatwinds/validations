package validations

import (
	"net/http"
	"regexp"

	"github.com/quantfall/rerror"
)

func ValidateRegEx(regex, value string) *rerror.Error {
	expression := regexp.MustCompile(regex)
	matches := expression.FindAllString(value, -1)
	if len(matches) != 1 {
		return rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "value '%s' does not match with regexp '%s'", value, regex)
	}

	if matches[0] != value {
		return rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "value '%s' does not match with regexp '%s'", value, regex)
	}

	return nil
}
