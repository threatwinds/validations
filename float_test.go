package validations_test

import (
	"testing"

	"github.com/threatwinds/validations"
)

func TestValidateFloat(t *testing.T) {
	validCases := []struct {
		name     string
		input    interface{}
		expected float64
	}{
		{
			name:     "valid float",
			input:    3.14,
			expected: 3.14,
		},
		{
			name:     "valid float",
			input:    42.0,
			expected: 42.0,
		},
	}

	invalidCases := []struct {
		name  string
		input interface{}
	}{
		{
			name:  "invalid string",
			input: "not a float",
		},
		{
			name:  "invalid bool",
			input: true,
		},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, _, err := validations.ValidateFloat(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if actual != tc.expected {
				t.Errorf("expected %v, but got %v", tc.expected, actual)
			}
		})
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := validations.ValidateFloat(tc.input)
			if err == nil {
				t.Fatalf("expected error, but got nil")
			}
		})
	}
}