package validations

import "testing"

func TestValidateString(t *testing.T) {
	str := "Hello"
	lstr := "hello"

	s1, _, err := ValidateString(str, true)
	if lstr != s1 {
		t.Errorf("strings are not equals")
	}

	if err != nil {
		t.Error(err)
	}

	s2, _, err := ValidateString(str, false)
	if str != s2 {
		t.Errorf("strings are not equals")
	}

	if err != nil {
		t.Error(err)
	}
}
