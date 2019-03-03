package gpsw06

import (
	"github.com/Nik-U/pbc"
)

// NewGPSW06 instantiates a GPSW06 from a set of attributes
func NewGPSW06(attrs []Attribute) (*GPSW06, error) {
	// Check ordering of attributes
	for i := range attrs {
		if uint(i) != attrs[i].id {
			return nil, ErrBadAttributeList
		}
	}

	pbc.SetCryptoRandom()

	return &GPSW06{
		attrs,
	}, nil
}

// Setup outputs a public key and a master key.
func (algo *GPSW06) Setup() (*PublicKey, *MasterKey) {
	var (
		t []*Zr // components of master key
		y *Zr   // component of master key
		T []*G2 // components of public key, g2^t
		Y *GT   // component of public key, e(g1, g2)^y
	)

	// For each attribute
	for range algo.universe {
		// choose a random number r from Zr as secret key for current attribute
		r := pairing.NewZr().Rand()

		// Calculate g2^r as public key relative to secret key
		// and store both r and g2^r
		T = append(T, pairing.NewG2().PowZn(g2, r))
		t = append(t, r)
	}

	// Choose a random number y from Zr as secret key
	y = pairing.NewZr().Rand()
	// Calculate e(g1, g2)^y as public key relative to secret key
	Y = pairing.NewGT().PowZn(e, y)

	return &PublicKey{
			T,
			Y,
		}, &MasterKey{
			t,
			y,
		}
}

// Encrypt takes as input a message msg, a set of attributes attrs and the public key
// and output the ciphertext.
func (algo *GPSW06) Encrypt(msg *Message, attrs map[int]struct{}, key *PublicKey) (*Ciphertext, error) {
	var (
		s      *Zr // Random number
		encMsg *GT // Encrypted Message
	)

	// Encrypted attribute keys
	encAttrs := make(map[int]*G2)

	attrLength := len(key.t)

	// Choose a random s
	s = pairing.NewZr().Rand()
	// Compute Y^s
	Ys := pairing.NewGT().PowZn(key.y, s)
	// Compute encrypted message, E' = M*Y^s
	encMsg = pairing.NewGT().Mul(msg.m, Ys)
	// Compute encrypted attribute key, E_i = T_i ^ s
	for attr := range attrs {
		if attrLength <= attr {
			return nil, ErrAttrOutOfRange
		}
		encAttrs[attr] = pairing.NewG2().PowZn(key.t[attr], s)
	}

	return &Ciphertext{attrs, encMsg, encAttrs}, nil
}

// KeyGen takes as input an access structure tree and the master key, and generate
// the corresponding decryption key
func (algo *GPSW06) KeyGen(tree Node, msk *MasterKey) (*DecryptKey, error) {
	// polynomials holds a mapping of Node to slice of coefficients for
	// the polynomial of corresponding node.
	// Length of each slice equals to Threshold of node
	polynomials := make(map[Node]*polynomial)

	// leaves stores the computed decryption keys of each of the leaf attributes
	leaves := make(map[int]*G1)

	// queue holds the children nodes which will be processed later.
	queue := []Node{tree}

	// Breadth first traversal of tree
	var current Node
	for len(queue) > 0 {
		// Dequeue
		current, queue = queue[0], queue[1:]

		// Define degree of polynomial
		polynomials[current] = newPolynomial(current.Threshold())

		// if current node is root
		if current.Parent() == nil {
			// Set q_r(0) as y
			polynomials[current].c[0] = pairing.NewZr().Set(msk.y)
		} else {
			// for any other node,
			// set q_x(0) = q_parent(x) (Index(x))
			index := pairing.NewZr().SetInt32(int32(current.Index()))
			polynomials[current].c[0] = polynomials[current.Parent()].evaluate(index)
		}

		// Randomly choose the rest of the coefficients to completely define q_x
		for i := 1; i < len(polynomials[current].c); i++ {
			polynomials[current].c[i] = pairing.NewZr().Rand()
		}

		switch node := current.(type) {
		case *leafNode:
			// Compute q_x(0) / t_i
			qx := polynomials[current].evaluate(zero).ThenDiv(msk.t[node.Attr])
			// Compute g^(q_x(0) / t_i)
			leaves[node.Attr] = pairing.NewG1().PowZn(g1, qx)
		case *nonLeafNode:
			// Enqueue the current node's children
			queue = append(queue, node.Children...)
		default:
			return nil, ErrUnknownNodeType
		}
	}

	n, err := tree.MarshalJSON()
	if err != nil {
		return nil, err
	}

	return &DecryptKey{leaves, n}, nil
}

// Decrypt takes ciphertext c and decryption key dk as input and returns the
// decrypted message if attributes in c Satisfy policy in dk.
func (algo *GPSW06) Decrypt(ct *Ciphertext, key *DecryptKey) (*Message, error) {
	tree, err := nodeFromJSON(key.tree)
	if err != nil {
		return nil, err
	}

	if !tree.Satisfy(ct.attrs) {
		return nil, ErrTreeNotSatisfied
	}

	Ys, err := algo.decryptNode(ct, key, tree)
	if err != nil {
		return nil, err
	}
	return &Message{pairing.NewGT().Div(ct.encMsg, Ys)}, nil
}

func (algo *GPSW06) decryptNode(ct *Ciphertext, key *DecryptKey, x Node) (*GT, error) {
	switch node := x.(type) {
	case *leafNode:
		if _, ok := ct.attrs[node.Attr]; ok {
			return pairing.NewGT().Pair(key.d[node.Attr], ct.encAttrs[node.Attr]), nil
		}
		return nil, ErrEncAttrNotExist
	case *nonLeafNode:
		type element struct {
			index *Zr
			fx    *GT
		}
		var sx []element
		for _, child := range node.Children {
			fz, _ := algo.decryptNode(ct, key, child)
			if fz != nil {
				sx = append(sx, element{
					pairing.NewZr().SetInt32(int32(child.Index())),
					fz,
				})
			}
		}
		if len(sx) < node.Threshold() {
			return nil, ErrTreeNotSatisfied
		}

		sx = sx[:node.Threshold()]

		fx := pairing.NewGT().Set1()
		for i, fz := range sx {
			// Compute lagrange coefficient
			coefficient := pairing.NewZr().Set1()
			for j := range sx {
				if i != j {
					// polynomial interpolation
					numerator := pairing.NewZr().Sub(zero, sx[j].index)
					denominator := pairing.NewZr().Sub(fz.index, sx[j].index)
					coefficient.Mul(coefficient, numerator.Div(numerator, denominator))
				}
			}
			temp := pairing.NewGT().PowZn(fz.fx, coefficient)
			fx.Mul(fx, temp)
		}
		return fx, nil
	default:
		return nil, ErrUnknownNodeType
	}
}
