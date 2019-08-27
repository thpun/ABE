package bsw07

import (
	"testing"
)

func TestConstants(t *testing.T) {
	if _, _, err := loadParams(_paramString, _g); err != nil {
		t.Error(err)
	}
}
