package validations

import (
	"fmt"
	"time"
)

func ValidateDate(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value is not string: %v", value)
	}

	tmp, err := time.Parse("2006-01-02", v)
	if err != nil {
		return "", "", err
	}

	ftime := tmp.Format("2006-01-02")
	return ftime, GenerateSHA3256(ftime), nil
}

func ValidateDatetime(value interface{}) (string, string, error) {
	v, ok := value.(string)
	if !ok {
		return "", "", fmt.Errorf("value not string: %v", value)
	}

	tmp, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return "", "", err
	}

	ftime := tmp.Format(time.RFC3339Nano)
	return ftime, GenerateSHA3256(ftime), nil
}
