package gpsw06

type nodeType uint

const (
	// Unexported constants
	leaf nodeType = iota
	nonLeaf
)

type node interface {
	nodeType() nodeType
}

type leafNode struct {
	att    uint
	parent *node
}

type nonLeafNode struct {
	att      uint
	gate     operator
	children []*node
}

func (l *leafNode) nodeType() nodeType {
	return leaf
}

func (n *nonLeafNode) nodeType() nodeType {
	return nonLeaf
}
