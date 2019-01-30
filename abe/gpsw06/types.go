package gpsw06

import (
	"math/big"

	"github.com/cloudflare/bn256"
)

type PublicKey struct {
	// contains filtered or unexported fields
	t []*bn256.G2
	y *bn256.GT
}

type DecryptKey struct {
	// contains filtered or unexported fields
	d map[uint]*bn256.G1
}

type MasterKey struct {
	// contains filtered or unexported fields
	t []*big.Int
	y *big.Int
}

type Message struct {
	// contains filtered or unexported fields
	m *bn256.GT
}

type Ciphertext struct {
	// contains filtered or unexported fields
	atts []uint
	eMsg *bn256.GT
	e    map[uint]*bn256.G2
}

// Marshal converts msg into a byte slice.
func (msg *Message) Marshal() []byte {
	return msg.m.Marshal()
}

// Unmarshal sets msg to the result of converting the output of Marshal back into
// a group element and then returns msg.
func (msg *Message) Unmarshal(b []byte) ([]byte, error) {
	return msg.m.Unmarshal(b)
}
