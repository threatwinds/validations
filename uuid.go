package validations

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

func ValidateUUID(value interface{}) (uuid.UUID, string, error) {
	v, ok := value.(string)
	if !ok {
		return uuid.UUID{}, "", fmt.Errorf("value is not string: %v", value)
	}

	u, err := uuid.Parse(strings.ToLower(v))
	if err != nil {
		return uuid.UUID{}, "", err
	}

	return u, GenerateSHA3256(u.String()), nil
}
