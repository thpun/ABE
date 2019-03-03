package gpsw06

import (
	"github.com/Nik-U/pbc"
)

type G1 = pbc.Element
type G2 = pbc.Element
type GT = pbc.Element
type Zr = pbc.Element
type Pairing = pbc.Pairing

type PublicKey struct {
	// contains filtered or unexported fields
	t []*G2
	y *GT
}

type DecryptKey struct {
	// contains filtered or unexported fields
	d    map[int]*G1
	tree []byte
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
	attrs    map[int]struct{}
	encMsg   *GT
	encAttrs map[int]*G2
}

type GPSW06 struct {
	universe []Attribute
}

type polynomial struct {
	c []*Zr
}

// NewMessage creates an empty Message.
func NewMessage() *Message {
	return &Message{
		pairing.NewGT(),
	}
}

// Rand set msg to a random value and returns msg.
func (msg *Message) Rand() *Message {
	msg.m.Rand()
	return msg
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

func newPolynomial(deg int) *polynomial {
	return &polynomial{make([]*Zr, deg)}
}

func (p *polynomial) evaluate(x *Zr) *Zr {
	output := pairing.NewZr()
	temp := pairing.NewZr().Set1()
	for i, c := range p.c {
		temp.Set1()
		if i != 0 {
			temp.PowZn(x, pairing.NewZr().SetInt32(int32(i)))
		}
		temp.Mul(temp, c)
		output.Add(output, temp)
	}
	return output
}
