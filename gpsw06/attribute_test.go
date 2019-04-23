package gpsw06

import "testing"

func TestNewAttributes(t *testing.T) {
	var labels = []string{
		"a",
		"b",
		"c",
		"d",
		"e",
		"something longer than a character",
	}

	attrs := NewAttributes(labels)

	if len(labels) != len(attrs) {
		t.Errorf("Length of attribute list does not match. (In: %d, Out: %d)", len(labels), len(attrs))
	} else {
		for i := range labels {
			if int(attrs[i].id) != i || attrs[i].label != labels[i] {
				t.Errorf("Content of attribute list does not match. (In: %v, Out: %v)", labels[i], attrs[i])
			}
		}
	}
}
