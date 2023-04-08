package validations

import (
	"fmt"
	"net/http"

	"github.com/quantfall/rerror"
)

func ValidateBoolean(value interface{}) (bool, string, *rerror.Error) {
	v, ok := value.(bool)
	if !ok {
		return false, "", rerror.ErrorF(http.StatusBadRequest, "value is not boolean: %v", value)
	}

	return v, GenerateSHA3256(fmt.Sprint(v)), nil
}
