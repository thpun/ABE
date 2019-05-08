package gpsw06

import (
	"encoding/base64"
	"encoding/json"

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

type publicKey struct {
	KeyType string   `json:"type"`
	T       [][]byte `json:"t"`
	Y       []byte   `json:"y"`
}

type DecryptKey struct {
	// contains filtered or unexported fields
	d    map[int]*G1
	tree []byte
}

type decryptKey struct {
	KeyType string         `json:"type"`
	D       map[int][]byte `json:"d"`
	Tree    []byte         `json:"tree"`
}

type MasterKey struct {
	// contains filtered or unexported fields
	t []*Zr
	y *Zr
}

type masterKey struct {
	KeyType string   `json:"type"`
	T       [][]byte `json:"t"`
	Y       []byte   `json:"y"`
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

type ciphertext struct {
	Msg   []byte         `json:"msg"`
	Attrs map[int][]byte `json:"attrs"`
}

type GPSW06 struct {
	universe []Attribute
}

type polynomial struct {
	c []*Zr
}

// Marshal converts pk into a byte slice.
func (pk *PublicKey) Marshal() ([]byte, error) {
	t := make([][]byte, 0)
	for i := range pk.t {
		t = append(t, pk.t[i].Bytes())
	}

	var y = pk.y.Bytes()

	str, err := json.Marshal(publicKey{"public", t, y})
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(str)), nil
}

// Unmarshal set pk to the result of converting the output of Marshal back into
// a public key structure and then return b.
func (pk *PublicKey) Unmarshal(b []byte) ([]byte, error) {
	str, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	var instance = publicKey{}
	if err := json.Unmarshal([]byte(str), &instance); err != nil {
		return nil, err
	} else if instance.KeyType != "public" {
		return nil, ErrExpectingPublicKey
	}

	var y *GT

	t := make([]*G2, 0)

	for i := range instance.T {
		t = append(t, pairing.NewG2().SetBytes(instance.T[i]))
	}
	y = pairing.NewGT().SetBytes(instance.Y)

	pk.t = t
	pk.y = y

	return b, nil
}

// Marshal converts dk into a byte slice.
func (dk *DecryptKey) Marshal() ([]byte, error) {
	d := make(map[int][]byte)
	for k, v := range dk.d {
		d[k] = v.Bytes()
	}

	str, err := json.Marshal(decryptKey{"private", d, dk.tree})
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(str)), nil
}

// Unmarshal set dk to the result of converting the output of Marshal back into
// a private key structure and then return b.
func (dk *DecryptKey) Unmarshal(b []byte) ([]byte, error) {
	str, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	var instance = decryptKey{}
	if err := json.Unmarshal([]byte(str), &instance); err != nil {
		return nil, err
	} else if instance.KeyType != "private" {
		return nil, ErrExpectingPrivateKey
	}

	d := make(map[int]*G1)

	for k, v := range instance.D {
		d[k] = pairing.NewG1().SetBytes(v)
	}

	dk.d = d
	dk.tree = instance.Tree

	return b, nil
}

// Marshal converts msk into a byte slice.
func (msk *MasterKey) Marshal() ([]byte, error) {
	t := make([][]byte, 0)
	for i := range msk.t {
		t = append(t, msk.t[i].Bytes())
	}

	var y = msk.y.Bytes()

	str, err := json.Marshal(publicKey{"master", t, y})
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(str)), nil
}

// Unmarshal set msk to the result of converting the output of Marshal back into
// a master key structure and then return b.
func (msk *MasterKey) Unmarshal(b []byte) ([]byte, error) {
	str, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	var instance = masterKey{}
	if err := json.Unmarshal([]byte(str), &instance); err != nil {
		return nil, err
	} else if instance.KeyType != "master" {
		return nil, ErrExpectingMasterKey
	}

	var y *Zr
	t := make([]*Zr, 0)

	for i := range instance.T {
		t = append(t, pairing.NewZr().SetBytes(instance.T[i]))
	}
	y = pairing.NewZr().SetBytes(instance.Y)

	msk.t = t
	msk.y = y

	return b, nil
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

// Marshal converts ct into a byte slice.
func (ct *Ciphertext) Marshal() ([]byte, error) {
	m := ct.encMsg.Bytes()
	a := make(map[int][]byte)
	for k, v := range ct.encAttrs {
		a[k] = v.Bytes()
	}

	str, err := json.Marshal(ciphertext{m, a})
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(str)), nil
}

// Unmarshal set ct to the result of converting the output of Marshal back into
// a ciphertext structure and then return b.
func (ct *Ciphertext) Unmarshal(b []byte) ([]byte, error) {
	str, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}

	var instance = ciphertext{}
	if err := json.Unmarshal([]byte(str), &instance); err != nil {
		return nil, err
	}

	m := pairing.NewGT().SetBytes(instance.Msg)
	a := make(map[int]struct{})
	encAttrs := make(map[int]*G2)

	for k, v := range instance.Attrs {
		a[k] = struct{}{}
		encAttrs[k] = pairing.NewG2().SetBytes(v)
	}

	ct.attrs = a
	ct.encMsg = m
	ct.encAttrs = encAttrs

	return b, nil
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
