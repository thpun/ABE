package bsw07

import (
	"bytes"
	"encoding/json"
	"testing"
)

var (
	algo   *BSW07
	cipher *Ciphertext
	msg    *Message
	msk    *MasterKey
	pk     *PublicKey
	dk     *DecryptKey
)

func TestNewGPSW06(t *testing.T) {
	_, err := NewBSW07()
	if err != nil {
		t.Errorf("Error (%v) during initializing GPSW06.", err)
	}
}

func TestGPSW06_Encrypt(t *testing.T) {
	algo, _ = NewBSW07()
	pk, msk = algo.Setup()

	tree := &leafNode{
		"a",
		nil,
	}

	msg = NewMessage().Rand()

	var err error
	cipher, err = algo.Encrypt(pk, msg, tree)
	if err != nil {
		t.Errorf("Error (%v) during encrypting. Msg: %v.", err, msg)
	}
}

func TestGPSW06_KeyGen(t *testing.T) {
	attrsForCipher := make(map[string]struct{})
	attrsForCipher["a"] = struct{}{}
	attrsForCipher["b"] = struct{}{}
	attrsForCipher["f"] = struct{}{}
	attrsForCipher["h"] = struct{}{}

	var err error
	dk, err = algo.KeyGen(msk, attrsForCipher)
	if err != nil {
		t.Errorf("Error (%v) during decryption key generation.", err)
	}
	t.Logf("Decryption key: %v", dk)
}

func TestGPSW06_Decrypt(t *testing.T) {
	t.Logf("Decryption key: %v", dk)
	t.Logf("%v", cipher)
	plain, err := algo.Decrypt(cipher, dk)
	if err != nil {
		t.Errorf("Error (%v) during decryption.", err)
		return
	}

	if !plain.M.E.Equals(msg.M.E) {
		t.Errorf("Message before encryption and after decryption differs.")
	}
}

func TestMsg_Marshal(t *testing.T) {
	data := msg.Marshal()

	msg2 := NewMessage()
	if err := msg2.Unmarshal(data); err != nil {
		t.Errorf("Error (%v) during unmarshaling", err)
		return
	}

	if !msg.M.E.Equals(msg2.M.E) {
		t.Errorf("Message before marshal and after unmarshal differs.")
	}
}

func eq(a, b map[string]*G) bool {
	if len(a) != len(b) {
		return false
	}

	for k, v := range a {
		if w, ok := b[k]; !ok || !v.E.Equals(w.E) {
			return false
		}
	}

	return true
}

func TestCiphertext_Marshal(t *testing.T) {
	data, err := json.Marshal(cipher)
	if err != nil {
		t.Errorf("Error (%v) during marshaling", err)
		return
	}

	ct2 := Ciphertext{}
	if err := json.Unmarshal(data, &ct2); err != nil {
		t.Errorf("Error (%v) during unmarshaling", err)
		return
	}

	if bytes.Compare(cipher.Tree, ct2.Tree) != 0 {
		t.Errorf("Trees differ")
		return
	} else if !cipher.Msg.E.Equals(ct2.Msg.E) {
		t.Errorf("Encrypted messages differ")
		return
	} else if !cipher.C.E.Equals(ct2.C.E) {
		t.Errorf("C differ")
		return
	} else if !eq(cipher.C1, ct2.C1) {
		t.Errorf("C1 differs")
		return
	} else if !eq(cipher.C2, ct2.C2) {
		t.Errorf("C2 differs")
		return
	}

	t.Logf("%v", cipher)
}
