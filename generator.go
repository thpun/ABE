package main

import (
	"fmt"

	"github.com/Nik-U/pbc"
)

func main() {
	pbc.SetCryptoRandom()
	params := pbc.GenerateF(160)
	pairing := params.NewPairing()

	fmt.Printf("--BEGIN--%s--END--\n", params.String())
	fmt.Printf("--BEGIN--%s--END--\n", pairing.NewG1().Rand().String())
	fmt.Printf("--BEGIN--%s--END--\n", pairing.NewG2().Rand().String())
}
