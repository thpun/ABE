package gpsw06

type Attribute struct {
	label string
	id    uint
}

func NewAttributes(labels []string) []Attribute {
	var attrs []Attribute

	for i, label := range labels {
		attrs = append(attrs, Attribute{label, uint(i)})
	}

	return attrs
}
