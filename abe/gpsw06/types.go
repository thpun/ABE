package gpsw06

import (
	"io"

	"github.com/Nik-U/pbc"
)

type G1 = pbc.Element
type G2 = pbc.Element
type GT = pbc.Element
type Zr = pbc.Element
type Params = pbc.Params

type PublicKey struct {
	// contains filtered or unexported fields
	t []*G2
	y *GT
}

type DecryptKey struct {
	// contains filtered or unexported fields
	d map[uint]*G1
}

type MasterKey struct {
	// contains filtered or unexported fields
	t []*Zr
	y *Zr
}

type Message struct {
	// contains filtered or unexported fields
	m *GT
}

type Ciphertext struct {
	// contains filtered or unexported fields
	atts []uint
	eMsg *GT
	e    map[uint]*G2
}

type GPSW06 struct {
	params   *Params
	r        *io.Reader
	universe []attribute
	g1       *G1
	g2       *G2
}

// Marshal converts msg into a byte slice.
func (msg *Message) Marshal() []byte {
	return msg.m.Bytes()
}

// Unmarshal sets msg to the result of converting the output of Marshal back into
// a group element and then returns msg.
func (msg *Message) Unmarshal(b []byte) ([]byte, error) {
	return msg.m.SetBytes(b).Bytes(), nil
}
