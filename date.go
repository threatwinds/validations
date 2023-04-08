package validations

import (
	"net/http"
	"time"

	"github.com/quantfall/rerror"
)

func ValidateDate(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, "value is not string: %v", value)
	}

	tmp, err := time.Parse("2006-01-02", v)
	if err != nil {
		return "", "", rerror.ErrorF(http.StatusBadRequest, err.Error())
	}

	ftime := tmp.Format("2006-01-02")
	return ftime, GenerateSHA3256(ftime), nil
}

func ValidateDatetime(value interface{}) (string, string, *rerror.Error) {
	v, ok := value.(string)
	if !ok {
		return "", "", rerror.ErrorF(http.StatusBadRequest, "value not string: %v", value)
	}

	tmp, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return "", "", rerror.ErrorF(http.StatusBadRequest, err.Error())
	}

	ftime := tmp.Format(time.RFC3339Nano)
	return ftime, GenerateSHA3256(ftime), nil
}
