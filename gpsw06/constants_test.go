package gpsw06

import (
	"testing"
)

func TestConstants(t *testing.T) {
	if _, _, _, err := loadParams(_paramString, _g1, _g2); err != nil {
		t.Error(err)
	}
}
