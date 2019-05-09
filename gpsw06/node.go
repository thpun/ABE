package gpsw06

import (
	"encoding/json"
)

type operator uint

const (
	or operator = iota
	and
)

type Node interface {
	Index() int
	Parent() Node
	Satisfy(map[int]struct{}) bool
	Threshold() int
	Equal(Node) bool
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

type leafNode struct {
	Attr   int
	parent Node
}

type nonLeafNode struct {
	Gate     operator
	parent   Node
	Children []Node
}

type trimLeaf struct {
	Attr int `json:"attr"`
}

type trimNonLeaf struct {
	Gate     operator `json:"gate"`
	Children []Node   `json:"children"`
}

type rawNonLeaf struct {
	Gate     operator          `json:"gate"`
	Children []json.RawMessage `json:"children"`
}

func (l *leafNode) Index() int {
	parent, ok := l.parent.(*nonLeafNode)
	if ok {
		for i := range parent.Children {
			if l == parent.Children[i] {
				return i + 1
			}
		}
	}
	return 0
}

func (l *leafNode) Parent() Node {
	return l.parent
}

func (l *leafNode) Satisfy(attrs map[int]struct{}) bool {
	_, ok := attrs[l.Attr]
	return ok
}

func (l *leafNode) Threshold() int {
	return 1
}

func (l *leafNode) Equal(node Node) bool {
	switch n2 := node.(type) {
	case *leafNode:
		return (l.Attr == n2.Attr) && ((l.parent != nil && n2.parent != nil) || (l.parent == n2.parent))
	case *nonLeafNode:
		return false
	default:
		return false
	}
}

func (l *leafNode) MarshalJSON() ([]byte, error) {
	return json.Marshal(trimLeaf{l.Attr})
}

func (l *leafNode) UnmarshalJSON(data []byte) error {
	var tl = trimLeaf{-1}
	if err := json.Unmarshal(data, &tl); err != nil {
		return err
	}
	if tl.Attr < 0 {
		return ErrBadNodeJSON
	}

	l.Attr = tl.Attr
	return nil
}

func (n *nonLeafNode) Index() int {
	parent, ok := n.parent.(*nonLeafNode)
	if ok {
		for i := range parent.Children {
			if n == parent.Children[i] {
				return i + 1
			}
		}
	}
	return 0
}

func (n *nonLeafNode) Parent() Node {
	return n.parent
}

func (n *nonLeafNode) Satisfy(attrs map[int]struct{}) bool {
	result := false

	switch n.Gate {
	case or:
		for i := 0; i < len(n.Children); i++ {
			if n.Children[i].Satisfy(attrs) {
				return true
			}
		}
		return false
	case and:
		for i := 0; i < len(n.Children) && n.Children[i].Satisfy(attrs); i, result = i+1, true {
		}
		return result
	default:
		return false
	}
}

func (n *nonLeafNode) Threshold() int {
	switch n.Gate {
	case or:
		return 1
	case and:
		return len(n.Children)
	default:
		return 1
	}
}

func (n *nonLeafNode) MarshalJSON() ([]byte, error) {
	return json.Marshal(trimNonLeaf{n.Gate, n.Children})
}

func (n *nonLeafNode) UnmarshalJSON(data []byte) error {
	var tnl = rawNonLeaf{or, make([]json.RawMessage, 0)}
	if err := json.Unmarshal(data, &tnl); err != nil {
		return err
	}

	if len(tnl.Children) <= 0 {
		return ErrBadNodeJSON
	}

	children := make([]Node, 0)

	for i := range tnl.Children {
		nc, err := NodeFromJSON(tnl.Children[i])
		if err != nil {
			return err
		}
		switch node := nc.(type) {
		case *leafNode:
			node.parent = n
		case *nonLeafNode:
			node.parent = n
		}
		children = append(children, nc)
	}

	n.Gate = tnl.Gate
	n.Children = children

	return nil
}

func (n *nonLeafNode) Equal(node Node) bool {
	switch n2 := node.(type) {
	case *leafNode:
		return false
	case *nonLeafNode:
		if n.Gate != n2.Gate || len(n.Children) != len(n2.Children) {
			return false
		}
		for i := range n.Children {
			if !n.Children[i].Equal(n2.Children[i]) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func NodeFromJSON(data []byte) (Node, error) {
	switch data[2] {
	case 'a':
		// Try leaf node
		l := &leafNode{0, nil}
		if err := l.UnmarshalJSON(data); err != nil {
			return nil, err
		}
		return l, nil
	case 'g':
		// Try non leaf node
		n1 := &nonLeafNode{or, nil, make([]Node, 0)}
		if err := n1.UnmarshalJSON(data); err != nil {
			return nil, err
		}
		return n1, nil
	default:
		return nil, ErrBadNodeJSON
	}
}
