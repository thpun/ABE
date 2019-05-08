package gpsw06

import (
	"bytes"
	"testing"
)

func TestEvaluate1(t *testing.T) {
	var (
		one      = pairing.NewZr().Set1()
		two      = pairing.NewZr().SetInt32(2)
		three    = pairing.NewZr().SetInt32(3)
		twoEight = pairing.NewZr().SetInt32(28)
	)

	f := newPolynomial(1)
	f.c[0] = pairing.NewZr().SetInt32(3)

	if !(f.evaluate(zero).Equals(three) && f.evaluate(one).Equals(three) && f.evaluate(two).Equals(three) && f.evaluate(twoEight).Equals(three)) {
		t.Errorf("Polynomial (degree 1) evaluated wrongly.")
	}
}

func TestEvaluate2(t *testing.T) {
	var (
		one      = pairing.NewZr().Set1()
		two      = pairing.NewZr().SetInt32(2)
		three    = pairing.NewZr().SetInt32(3)
		four     = pairing.NewZr().SetInt32(4)
		seven    = pairing.NewZr().SetInt32(7)
		nine     = pairing.NewZr().SetInt32(9)
		ten      = pairing.NewZr().SetInt32(10)
		twoEight = pairing.NewZr().SetInt32(28)
	)
	f := newPolynomial(2)
	f.c[1] = pairing.NewZr().SetInt32(3)
	f.c[0] = pairing.NewZr().Set1()

	if !(f.evaluate(zero).Equals(one) && f.evaluate(one).Equals(four) && f.evaluate(two).Equals(seven) && f.evaluate(three).Equals(ten) && f.evaluate(nine).Equals(twoEight)) {
		t.Errorf("Polynomial (degree 2) evaluated wrongly.")
	}
}

func TestEvaluate3(t *testing.T) {
	var (
		num = pairing.NewZr().Rand()
		one = pairing.NewZr().Set1()
	)

	f := newPolynomial(1)
	f.c[0] = num

	if !(f.evaluate(zero).Equals(num) && f.evaluate(one).Equals(num)) {
		t.Errorf("Polynomial (degree 1, big number) evaluated wrongly.")
	}
}

func TestPublicKey_Marshal(t *testing.T) {
	pk := PublicKey{[]*G2{
		pairing.NewG2().Rand(),
		pairing.NewG2().Rand(),
		pairing.NewG2().Rand(),
		pairing.NewG2().Rand(),
		pairing.NewG2().Rand(),
		pairing.NewG2().Rand(),
		pairing.NewG2().Rand(),
	}, pairing.NewGT().Rand()}

	pkStr, err := pk.Marshal()
	if err != nil {
		t.Errorf("Error occurred during marshalling public key: %v", err)
	}

	pk2 := PublicKey{}
	if _, err := pk2.Unmarshal(pkStr); err != nil {
		t.Errorf("Error occurred during unmarshalling public key: %v", err)
	}

	if len(pk.t) != len(pk2.t) {
		t.Errorf("Public key length not match")
	}

	eq := true

	for i := range pk.t {
		eq = eq && pk.t[i].Equals(pk2.t[i])
	}

	if !eq {
		t.Errorf("Public key t value not match")
	}

	if !pk.y.Equals(pk2.y) {
		t.Errorf("Publick key y value not match")
	}
}

func TestMasterKey_Marshal(t *testing.T) {
	msk := MasterKey{[]*Zr{
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
		pairing.NewZr().Rand(),
	}, pairing.NewZr().Rand()}

	mskStr, err := msk.Marshal()
	if err != nil {
		t.Errorf("Error occurred during marshalling master key: %v", err)
	}

	msk2 := MasterKey{}
	if _, err := msk2.Unmarshal(mskStr); err != nil {
		t.Errorf("Error occurred during unmarshalling master key: %v", err)
	}

	if len(msk.t) != len(msk2.t) {
		t.Errorf("Master key length not match")
	}

	eq := true

	for i := range msk.t {
		eq = eq && msk.t[i].Equals(msk2.t[i])
	}

	if !eq {
		t.Errorf("Master key t value not match")
	}

	if !msk.y.Equals(msk2.y) {
		t.Errorf("Master key y value not match")
	}
}

func TestDecryptKey_Marshal(t *testing.T) {
	d := make(map[int]*G1)
	d[1] = pairing.NewG1().Rand()
	d[3] = pairing.NewG1().Rand()
	d[30] = pairing.NewG1().Rand()
	d[302] = pairing.NewG1().Rand()
	d[61303] = pairing.NewG1().Rand()
	d[94613] = pairing.NewG1().Rand()
	d[111113] = pairing.NewG1().Rand()
	d[42584] = pairing.NewG1().Rand()
	d[354] = pairing.NewG1().Rand()

	dk := DecryptKey{d, []byte("tree")}

	dkStr, err := dk.Marshal()
	if err != nil {
		t.Errorf("Error occurred during marshalling private key: %v", err)
	}

	dk2 := DecryptKey{}
	if _, err := dk2.Unmarshal(dkStr); err != nil {
		t.Errorf("Error occurred during unmarshalling private key: %v", err)
	}

	if bytes.Compare(dk.tree, dk2.tree) != 0 {
		t.Errorf("Private key tree value not match.\n\t1: %v\n\t2: %v", dk.tree, dk2.tree)
	}

	if len(dk.d) != len(dk2.d) {
		t.Errorf("Private key map size not match")
	}

	eq := true
	for i, v := range dk.d {
		v2, ok := dk2.d[i]
		eq = eq && ok && v.Equals(v2)
	}

	if !eq {
		t.Errorf("Private key d value not match")
	}
}

func TestCiphertext_Marshal(t *testing.T) {
	a := make(map[int]struct{})
	ea := make(map[int]*G2)

	for i := range []int{1, 2, 6, 9, 11, 99, 1654, 889416, 654981} {
		a[i] = struct{}{}
		ea[i] = pairing.NewG2().Rand()
	}

	ct := Ciphertext{a, pairing.NewGT().Rand(), ea}

	ctStr, err := ct.Marshal()
	if err != nil {
		t.Errorf("Error occurred during marshalling ciphertext: %v", err)
	}

	ct2 := Ciphertext{}
	if _, err := ct2.Unmarshal(ctStr); err != nil {
		t.Errorf("Error occurred during unmarshalling ciphertext: %v", err)
	}

	if !ct.encMsg.Equals(ct2.encMsg) {
		t.Errorf("Private key msg value not match")
	}

	if len(ct.attrs) != len(ct2.attrs) {
		t.Errorf("Private key attrs size not match")
	}

	eq := true
	for i := range ct.attrs {
		_, ok := ct2.attrs[i]
		eq = eq && ok
	}

	if !eq {
		t.Errorf("Ciphertext attrs value not match")
	}

	if len(ct.encAttrs) != len(ct2.encAttrs) {
		t.Errorf("Private key encAttrs size not match")
	}

	for i, v := range ct.encAttrs {
		v2, ok := ct2.encAttrs[i]
		eq = eq && ok && v.Equals(v2)
	}

	if !eq {
		t.Errorf("Ciphertext encAttrs value not match")
	}
}
