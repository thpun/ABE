package bsw07

import (
	"testing"
)

var data []byte

func TestLeafNode_MarshalJSON(t *testing.T) {
	var l *leafNode = &leafNode{"TestLeafNode_MarshalJSON", nil}

	var err error
	data, err = l.MarshalJSON()
	if err != nil {
		t.Errorf("Error durting serializing leaf node: %v", err)
		return
	}

	t.Logf("JSON: %s", string(data))
}

func TestLeafNode_UnmarshalJSON(t *testing.T) {
	var l = &leafNode{"TestLeafNode_UnmarshalJSON", nil}
	var l2 leafNode
	if err := l2.UnmarshalJSON(data); err != nil {
		t.Errorf("Error during de-serializing leaf node: %v", err)
		return
	}

	if *l != l2 {
		t.Errorf("leaf node serialization does not match with de-serialization")
	}
}

func buildTree() *nonLeafNode {
	n := &nonLeafNode{or, nil, make([]Node, 0)}
	n.Children = append(n.Children, &leafNode{"1", n}, &leafNode{"2", n})

	nc := &nonLeafNode{and, n, make([]Node, 0)}
	nc.Children = append(nc.Children, &leafNode{"3", nc}, &leafNode{"4", nc})
	n.Children = append(n.Children, nc)

	return n
}

func TestNonLeafNode_MarshalJSON(t *testing.T) {
	n := buildTree()

	var err error
	data, err = n.MarshalJSON()
	if err != nil {
		t.Errorf("Error durting serializing non-leaf node: %v", err)
		return
	}

	t.Logf("JSON: %s", string(data))
}

func TestNonLeafNode_UnmarshalJSON(t *testing.T) {
	t.Logf("JSON: %s", string(data))
	n := buildTree()
	var n1 nonLeafNode
	if err := n1.UnmarshalJSON(data); err != nil {
		t.Errorf("Error during de-serializing non-leaf node: %v", err)
		return
	}

	if !n1.Equal(n) {
		t.Errorf("non-leaf node serialization does not match with de-serialization")
		str, _ := n1.MarshalJSON()
		t.Logf("%s", string(str))
	}
}
