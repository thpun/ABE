package bsw07

import (
	"testing"
)

func TestEvaluate1(t *testing.T) {
	var (
		one      = &Element{"Zr", pairing.P.NewZr().Set1()}
		two      = &Element{"Zr", pairing.P.NewZr().SetInt32(2)}
		three    = &Element{"Zr", pairing.P.NewZr().SetInt32(3)}
		twoEight = &Element{"Zr", pairing.P.NewZr().SetInt32(28)}
	)

	f := newPolynomial(1)
	f.c[0] = &Element{"Zr", pairing.P.NewZr().SetInt32(3)}

	if !(f.evaluate(&Element{"Zr", zero}).E.Equals(three.E) && f.evaluate(one).E.Equals(three.E) && f.evaluate(two).E.Equals(three.E) && f.evaluate(twoEight).E.Equals(three.E)) {
		t.Errorf("Polynomial (degree 1) evaluated wrongly.")
	}
}

func TestEvaluate2(t *testing.T) {
	var (
		one      = &Element{"Zr", pairing.P.NewZr().Set1()}
		two      = &Element{"Zr", pairing.P.NewZr().SetInt32(2)}
		three    = &Element{"Zr", pairing.P.NewZr().SetInt32(3)}
		four     = &Element{"Zr", pairing.P.NewZr().SetInt32(4)}
		seven    = &Element{"Zr", pairing.P.NewZr().SetInt32(7)}
		nine     = &Element{"Zr", pairing.P.NewZr().SetInt32(9)}
		ten      = &Element{"Zr", pairing.P.NewZr().SetInt32(10)}
		twoEight = &Element{"Zr", pairing.P.NewZr().SetInt32(28)}
	)
	f := newPolynomial(2)
	f.c[1] = &Element{"Zr", pairing.P.NewZr().SetInt32(3)}
	f.c[0] = &Element{"Zr", pairing.P.NewZr().Set1()}

	if !(f.evaluate(&Element{"Zr", zero}).E.Equals(one.E) && f.evaluate(one).E.Equals(four.E) && f.evaluate(two).E.Equals(seven.E) && f.evaluate(three).E.Equals(ten.E) && f.evaluate(nine).E.Equals(twoEight.E)) {
		t.Errorf("Polynomial (degree 2) evaluated wrongly.")
	}
}

func TestEvaluate3(t *testing.T) {
	var (
		num = &Element{"Zr", pairing.P.NewZr().Rand()}
		one = &Element{"Zr", pairing.P.NewZr().Set1()}
	)

	f := newPolynomial(1)
	f.c[0] = num

	if !(f.evaluate(&Element{"Zr", zero}).E.Equals(num.E) && f.evaluate(one).E.Equals(num.E)) {
		t.Errorf("Polynomial (degree 1, big number) evaluated wrongly.")
	}
}
