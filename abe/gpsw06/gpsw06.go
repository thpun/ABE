package gpsw06

import (
	"io"

	"github.com/cloudflare/bn256"
)

type GPSW06 struct {
	r        *io.Reader
	universe []attribute
	g1       *bn256.G1
	g2       *bn256.G2
}

func (algo *GPSW06) Setup() (PublicKey, MasterKey, error) {

}

func (algo *GPSW06) Encrypt(msg Message, atts []uint, key PublicKey) (Ciphertext, error) {

}

func (algo *GPSW06) KeyGen(Tree, msk MasterKey) (DecryptKey, error) {

}

func (algo *GPSW06) Decrypt(ciphertext Ciphertext, dk DecryptKey) (Message, error) {

}

func (algo *GPSW06) decryptNode(ciphertext Ciphertext, key DecryptKey, attId uint) {

}
