package gpsw06

import "testing"

var (
	labels = []string{
		"a",
		"b",
		"c",
		"d",
		"e",
		"f",
		"g",
	}

	algo   *GPSW06
	cipher *Ciphertext
	msg    *Message
	msk    *MasterKey
	pk     *PublicKey
	dk     *DecryptKey
)

func TestNewGPSW06(t *testing.T) {
	_, err := NewGPSW06(NewAttributes(labels))
	if err != nil {
		t.Errorf("Error (%v) during initializing GPSW06.", err)
	}
}

func TestGPSW06_Encrypt(t *testing.T) {
	algo, _ = NewGPSW06(NewAttributes(labels))
	pk, msk = algo.Setup()

	attrsForCipher := make(map[int]struct{})
	attrsForCipher[1] = struct{}{}
	attrsForCipher[2] = struct{}{}
	attrsForCipher[4] = struct{}{}
	attrsForCipher[6] = struct{}{}

	msg = NewMessage().Rand()

	var err error
	cipher, err = algo.Encrypt(msg, attrsForCipher, pk)
	if err != nil {
		t.Errorf("Error (%v) during encrypting. Msg: %v.", err, msg)
	}
}

func TestGPSW06_KeyGen(t *testing.T) {
	tree := &leafNode{
		1,
		nil,
	}

	var err error
	dk, err = algo.KeyGen(tree, msk)
	if err != nil {
		t.Errorf("Error (%v) during decryption key generation.", err)
	}
	t.Logf("Decryption key: %v", dk)
	t.Logf("%v", dk.d[1])
	t.Logf("%v", dk.tree)
}

func TestGPSW06_Decrypt(t *testing.T) {
	t.Logf("Decryption key: %v", dk)
	t.Logf("%v", cipher)
	plain, err := algo.Decrypt(cipher, dk)
	if err != nil {
		t.Errorf("Error (%v) during decryption.", err)
		return
	}

	if !plain.m.Equals(msg.m) {
		t.Errorf("Message before encryption and after decryption differs.")
	}
}
