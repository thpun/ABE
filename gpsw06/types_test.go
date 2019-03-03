package gpsw06

import "testing"

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
