package validations

import (
	"net/http"

	"github.com/quantfall/rerror"
)

func ValidateObject(value interface{}) (string, string, *rerror.Error) {
	s1, h1, e1 := ValidateUUID(value)
	if e1 == nil {
		return s1.String(), h1, nil
	}
	s2, h2, e2 := ValidateMD5(value)
	if e2 == nil {
		return s2, h2, nil
	}
	s3, h3, e3 := ValidateSHA3256(value)
	if e3 == nil {
		return s3, h3, nil
	}

	return "", "", rerror.ErrorF(false, http.StatusBadRequest, "TYPE_VALIDATION", "invalid object: %v", value)
}
