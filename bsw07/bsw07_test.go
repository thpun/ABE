package bsw07

import "testing"

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
