package bsw07

import (
	"encoding/json"

	"github.com/Nik-U/pbc"
)

type Element struct {
	Field string       `json:"field"`
	E     *pbc.Element `json:"e"`
}

type tempEl struct {
	Field string          `json:"field"`
	E     json.RawMessage `json:"e"`
}

type G = Element
type GT = Element
type Zr = Element
type Pairing struct {
	P *pbc.Pairing
}

func (p *Pairing) NewG() *Element {
	return &Element{
		Field: "G",
		E:     p.P.NewG1(),
	}
}

func (p *Pairing) NewGT() *Element {
	return &Element{
		Field: "GT",
		E:     p.P.NewGT(),
	}
}

func (p *Pairing) NewZr() *Element {
	return &Element{
		Field: "Zr",
		E:     p.P.NewZr(),
	}
}

type PublicKey struct {
	KeyType string `json:"type"`
	H       *G     `json:"h"`
	E       *GT    `json:"e"`
}

func NewPublicKey(h *G, e *GT) *PublicKey {
	return &PublicKey{
		KeyType: "public",
		H:       h,
		E:       e,
	}
}

type DecryptKey struct {
	KeyType string              `json:"type"`
	S       map[string]struct{} `json:"s"`
	D       *G                  `json:"d"`
	F       *G                  `json:"f"`
	D1      map[string]*G       `json:"d1"`
	D2      map[string]*G       `json:"d2"`
}

func NewDecryptKey(s map[string]struct{}, d, f *G, d1, d2 map[string]*G) *DecryptKey {
	return &DecryptKey{
		KeyType: "private",
		S:       s,
		D:       d,
		F:       f,
		D1:      d1,
		D2:      d2,
	}
}

type MasterKey struct {
	KeyType string `json:"type"`
	A       *G     `json:"a"`
	B       *Zr    `json:"b"`
}

func NewMasterKey(a *G, b *Zr) *MasterKey {
	return &MasterKey{
		KeyType: "master",
		A:       a,
		B:       b,
	}
}

type Message struct {
	M *GT `json:"m"`
}

type Ciphertext struct {
	Tree []byte        `json:"t"`
	Msg  *GT           `json:"msg"`
	C    *G            `json:"c"`
	C1   map[string]*G `json:"c1"`
	C2   map[string]*G `json:"c2"`
}

func NewCiphertext(t []byte, msg *GT, c *G, c1, c2 map[string]*G) *Ciphertext {
	return &Ciphertext{
		Tree: t,
		Msg:  msg,
		C:    c,
		C1:   c1,
		C2:   c2,
	}
}

type BSW07 struct {
}

type polynomial struct {
	c []*Zr
}

// Element implements encoding/json.Marshaler
func (e *Element) MarshalJSON() ([]byte, error) {
	return json.Marshal(tempEl{e.Field, e.E.Bytes()})
}

// Element implements encoding/jsonUnmarshaler
func (e *Element) UnmarshalJSON(b []byte) error {
	temp := &tempEl{}
	if err := json.Unmarshal(b, temp); err != nil {
		return err
	}

	switch temp.Field {
	case "G":
		e.E = pairing.P.NewG1().SetBytes(temp.E)
	case "GT":
		e.E = pairing.P.NewGT().SetBytes(temp.E)
	case "Zr":
		e.E = pairing.P.NewZr().SetBytes(temp.E)
	}

	e.Field = temp.Field

	return nil
}

// NewMessage creates an empty Message.
func NewMessage() *Message {
	return &Message{pairing.NewGT()}
}

// Rand set msg to a random value and returns msg.
func (msg *Message) Rand() *Message {
	msg.M.E.Rand()
	return msg
}

func newPolynomial(deg int) *polynomial {
	return &polynomial{make([]*Zr, deg)}
}

func (p *polynomial) evaluate(x *Zr) *Zr {
	output := pairing.NewZr()
	temp := pairing.NewZr()
	temp.E.Set1()
	for i, c := range p.c {
		temp.E.Set1()
		if i != 0 {
			temp.E.PowZn(x.E, pairing.P.NewZr().SetInt32(int32(i)))
		}
		temp.E.Mul(temp.E, c.E)
		output.E.Add(output.E, temp.E)
	}
	return output
}
