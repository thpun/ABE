package bsw07

import (
	"crypto/sha256"

	"github.com/Nik-U/pbc"
)

func hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// NewBSW07 instantiates a BSW07 from a set of attributes
func NewBSW07() (*BSW07, error) {
	pbc.SetCryptoRandom()

	return &BSW07{}, nil
}

// Setup outputs a public key and a master key.
func (algo *BSW07) Setup() (*PublicKey, *MasterKey) {
	var (
		a  *Zr = pairing.NewZr()
		b  *Zr = pairing.NewZr()
		h  *G  = pairing.NewG()
		eg *GT = pairing.NewGT()
		ga *G  = pairing.NewG()
	)

	// Choose a random number a, b from Zr as secret key
	a.E.Rand()
	b.E.Rand()

	// Calculate g^a, h = g^b, e = e(g,g)^a as public key relative to secret key
	ga.E.PowZn(g.E, a.E)
	h.E.PowZn(g.E, b.E)
	eg.E.PowZn(e, a.E)

	return NewPublicKey(h, eg), NewMasterKey(ga, b)
}

// Encrypt takes as input the public key, message and the access structure tree, and output
// the ciphertext.
func (algo *BSW07) Encrypt(key *PublicKey, msg *Message, tree Node) (*Ciphertext, error) {
	// polynomials holds a mapping of Node to slice of coefficients for
	// the polynomial of corresponding node.
	// Length of each slice equals to Threshold of node
	polynomials := make(map[Node]*polynomial)

	// c1, c2 store the computed ciphertext of each of leaf attribute
	c1 := make(map[string]*G)
	c2 := make(map[string]*G)

	// queue holds the children nodes which will be processed later.
	queue := []Node{tree}

	// randomly choose s
	s := pairing.NewZr()
	s.E.Rand()

	// Compute msg = M * e(g,g)^(a*s)
	encMsg := pairing.NewGT()
	// (e(g,g)^a)^s = e(g,g)^(a*s)
	encMsg.E.PowZn(key.E.E, s.E)
	// M * e(g,g)^(a*s)
	encMsg.E.Mul(msg.M.E, encMsg.E)

	// Compute c = h^s
	c := pairing.NewG()
	c.E.PowZn(key.H.E, s.E)

	// Breadth first traversal of tree
	var current Node
	for len(queue) > 0 {
		// Dequeue
		current, queue = queue[0], queue[1:]

		// Define degree of polynomial
		polynomials[current] = newPolynomial(current.Threshold())

		// if current node is root
		if current.Parent() == nil {
			// Set q_r(0) as s
			polynomials[current].c[0] = pairing.NewZr()
			polynomials[current].c[0].E.Set(s.E)
		} else {
			// For any other node,
			// Set q_x(0) as q_parent(x) (Index(x))
			index := pairing.NewZr()
			index.E.SetInt32(int32(current.Index()))
			polynomials[current].c[0] = polynomials[current.Parent()].evaluate(index)
		}

		// Randomly choose the rest of the coefficients to completely define q_x
		for i := 1; i < len(polynomials[current].c); i++ {
			polynomials[current].c[i] = pairing.NewZr()
			polynomials[current].c[i].E.Rand()
		}

		switch node := current.(type) {
		case *leafNode:
			// Compute c1 = g^q_y(0)
			cY := pairing.NewG()
			cY.E.PowZn(g.E, polynomials[current].c[0].E)

			// Compute c2 = H(y)^q_y(0)
			cY2 := pairing.NewG()
			cY2.E.SetFromHash(hash([]byte(node.Attr)))
			cY2.E.PowZn(cY2.E, polynomials[current].c[0].E)

			c1[string(node.Attr)] = cY
			c2[string(node.Attr)] = cY2
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

	return NewCiphertext(n, encMsg, c, c1, c2), nil
}

// KeyGen takes as input a set of attributes and the master key, and generate
// the corresponding decryption key
func (algo *BSW07) KeyGen(msk *MasterKey, attrs map[string]struct{}) (*DecryptKey, error) {
	// randomly choose r
	r := pairing.NewZr()
	r.E.Rand()

	// Compute d = g^((a+r)/b)
	d := pairing.NewG()
	// d = g^r
	d.E.PowZn(g.E, r.E)
	// d = g^a * g^r = g^(a+r)
	d.E.Mul(msk.A.E, d.E)
	bReciprocal := pairing.NewZr()
	bReciprocal.E.Invert(msk.B.E)
	// d = (g^(a+r))^(1/b) = g^((a+r)/b)
	d.E.PowZn(d.E, bReciprocal.E)

	// Compute f = g^(1/b)
	f := pairing.NewG()
	f.E.PowZn(g.E, bReciprocal.E)

	d1 := make(map[string]*G)
	d2 := make(map[string]*G)
	// For each attribute
	for attr := range attrs {
		// randomly choose rJ
		rJ := pairing.NewZr()
		rJ.E.Rand()
		// Compute dJ = g^r * H(j)^rJ
		dJ := pairing.NewG()
		dJ.E.PowZn(g.E, r.E)
		h := pairing.NewG()
		h.E.SetFromHash(hash([]byte(attr)))
		h.E.PowZn(h.E, rJ.E)
		dJ.E.Mul(dJ.E, h.E)

		// Compute dJ' = g^rJ
		dJ2 := pairing.NewG()
		dJ2.E.PowZn(g.E, rJ.E)

		d1[string(attr)] = dJ
		d2[string(attr)] = dJ2
	}

	return NewDecryptKey(attrs, d, f, d1, d2), nil
}

// Delegate takes in a secret key and a set of attribute subset to the one in secret key,
// and generate the corresponding delegated secret key
func (algo *BSW07) Delegate(dk *DecryptKey, attrs map[string]struct{}) (*DecryptKey, error) {
	// randomly pick r
	r := pairing.NewZr()
	r.E.Rand()

	// Compute d_1 = d_0*f^r
	d := pairing.NewG()
	d.E.PowZn(dk.F.E, r.E)
	d.E.Mul(dk.D.E, d.E)

	d1 := make(map[string]*G)
	d2 := make(map[string]*G)
	for attr := range attrs {
		if _, ok := dk.D1[string(attr)]; !ok {
			return nil, ErrSubsetAttrNotExist
		}

		// Randomly choose rK
		rK := pairing.NewZr()
		rK.E.Rand()

		// Compute dK = dJ * g^r * H(k) ^rK
		dK := pairing.NewG()
		// g^r
		dK.E.PowZn(g.E, r.E)
		h := pairing.NewG()
		h.E.SetFromHash(hash([]byte(attr)))
		// H(k)^rK
		h.E.PowZn(h.E, rK.E)
		// g^r * H(k)^rK
		dK.E.Mul(dK.E, h.E)
		// dK = dJ * g^r * H(k) ^rK
		dK.E.Mul(dk.D1[string(attr)].E, dK.E)

		// Compute dK' = dJ' * g^rK
		dK2 := pairing.NewG()
		// g^rK
		dK2.E.PowZn(g.E, rK.E)
		// dJ' * g^rK
		dK2.E.Mul(dk.D2[string(attr)].E, dK2.E)

		d1[string(attr)] = dK
		d2[string(attr)] = dK2
	}

	return NewDecryptKey(attrs, d, dk.F, d1, d2), nil
}

// Decrypt takes ciphertext c and decryption key dk as input and returns the
// decrypted message if attributes in dk Satisfy policy in ct.
func (algo *BSW07) Decrypt(ct *Ciphertext, key *DecryptKey) (*Message, error) {
	tree, err := NodeFromJSON(ct.Tree)
	if err != nil {
		return nil, err
	}

	if !tree.Satisfy(key.S) {
		return nil, ErrTreeNotSatisfied
	}

	a, err := algo.decryptNode(ct, key, tree)
	if err != nil {
		return nil, err
	}

	// Compute encMsg / (e(C, D)/A)
	m := pairing.NewGT()
	// e(C, D)
	m.E.Pair(ct.C.E, key.D.E)
	// e(C, D) / A
	m.E.Div(m.E, a.E)
	// encMsg / (e(C, D) / A)
	m.E.Div(ct.Msg.E, m.E)

	return &Message{m}, nil
}

func (algo *BSW07) decryptNode(ct *Ciphertext, key *DecryptKey, x Node) (*GT, error) {
	switch node := x.(type) {
	case *leafNode:
		if _, ok := key.S[string(node.Attr)]; ok {
			// Compute e(D_i, C_x)/e(D'_i, C'_x)
			numerator := pairing.NewGT()
			denominator := pairing.NewGT()
			// e(D_i, C_x)
			numerator.E.Pair(key.D1[string(node.Attr)].E, ct.C1[string(node.Attr)].E)
			// e(D'_i, C'_x)
			denominator.E.Pair(key.D2[string(node.Attr)].E, ct.C2[string(node.Attr)].E)
			// e(D_i, C_x)/e(D'_i, C'_x)
			numerator.E.Div(numerator.E, denominator.E)

			return numerator, nil
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
				index := pairing.NewZr()
				index.E.SetInt32(int32(child.Index()))
				sx = append(sx, element{
					index,
					fz,
				})
			}
		}
		if len(sx) < node.Threshold() {
			return nil, ErrTreeNotSatisfied
		}

		sx = sx[:node.Threshold()]

		fx := pairing.NewGT()
		fx.E.Set1()
		for i, fz := range sx {
			// Compute lagrange coefficient
			coefficient := pairing.NewZr()
			coefficient.E.Set1()
			for j := range sx {
				if i != j {
					// polynomial interpolation
					numerator := pairing.NewZr()
					numerator.E.Sub(zero, sx[j].index.E)
					denominator := pairing.NewZr()
					denominator.E.Sub(fz.index.E, sx[j].index.E)
					coefficient.E.Mul(coefficient.E, numerator.E.Div(numerator.E, denominator.E))
				}
			}
			temp := pairing.NewGT()
			temp.E.PowZn(fz.fx.E, coefficient.E)
			fx.E.Mul(fx.E, temp.E)
		}
		return fx, nil
	default:
		return nil, ErrUnknownNodeType
	}
}
