package validations_test

import (
	"testing"

	"github.com/threatwinds/validations"
)

func TestValidateBoolean(t *testing.T) {
	validCases := []struct {
		name     string
		input    interface{}
		expected bool
	}{
		{
			name:     "valid boolean true",
			input:    true,
			expected: true,
		},
		{
			name:     "valid boolean false",
			input:    false,
			expected: false,
		},
	}

	invalidCases := []struct {
		name  string
		input interface{}
	}{
		{
			name:  "invalid boolean",
			input: "not a boolean",
		},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, _, err := validations.ValidateBoolean(tc.input)
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
			_, _, err := validations.ValidateBoolean(tc.input)
			if err == nil {
				t.Fatalf("expected error, but got nil")
			}
		})
	}
}