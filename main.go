// Welcome to the gnark playground!
package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// gnark is a zk-SNARK library written in Go. Circuits are regular structs.
// The inputs must be of type frontend.Variable and make up the witness.
// The witness has a
//   - secret part --> known to the prover only
//   - public part --> known to the prover and the verifier
type MyCircuit struct {
	X frontend.Variable `gnark:"x"`       // x  --> secret visibility (default)
	Y frontend.Variable `gnark:",public"` // Y  --> public visibility
}

// Define declares the circuit logic. The compiler then produces a list of constraints
// which must be satisfied (valid witness) in order to create a valid zk-SNARK
func (circuit *MyCircuit) Define(api frontend.API) error {
	// compute x**3 and store it in the local variable x3.
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)

	// compute x**3 + x + 5 and store it in the local variable res
	res := api.Add(x3, circuit.X, 5)

	// assert that the statement x**3 + x + 5 == y is true.
	api.AssertIsEqual(circuit.Y, res)
	return nil
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	var myCircuit MyCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	check(err)
	r1cs := ccs.(*cs.R1CS)
	constraints, res := r1cs.GetConstraints()
	for i, c := range constraints {
		fmt.Printf("constraint %d: %v\n", i, c.String(res))
		fmt.Printf("  constraint L %d: %v\n", i, c.L.String(res))
		fmt.Printf("  constraint L raw %d: %v\n", i, c.L)
		for j, term := range c.L {
			fmt.Printf("    term %d: coeff %v, coeff str %v, var %v, var name %v\n", j, term.CoeffID(), res.CoeffToString(term.CoeffID()), term.WireID(), res.VariableToString(term.WireID()))
		}
		fmt.Printf("  constraint R %d: %v\n", i, c.R.String(res))
		fmt.Printf("  constraint R raw %d: %v\n", i, c.R)
		for j, term := range c.R {
			fmt.Printf("    term %d: coeff %v, coeff str %v, var %v, var name %v\n", j, term.CoeffID(), res.CoeffToString(term.CoeffID()), term.WireID(), res.VariableToString(term.WireID()))
		}
		fmt.Printf("  constraint O %d: %v\n", i, c.O.String(res))
		fmt.Printf("  constraint O raw %d: %v\n", i, c.O)
		for j, term := range c.O {
			fmt.Printf("    term %d: coeff %v, coeff str %v, var %v, var name %v\n", j, term.CoeffID(), res.CoeffToString(term.CoeffID()), term.WireID(), res.VariableToString(term.WireID()))
		}
	}

	assignment := MyCircuit{X: 3, Y: 35}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	check(err)

	opt, err := backend.NewProverConfig()
	check(err)

	a := make([]fr.Element, len(r1cs.Constraints))
	b := make([]fr.Element, len(r1cs.Constraints))
	c := make([]fr.Element, len(r1cs.Constraints))
	w := witness.Vector().(fr.Vector)

	wireValues, err := r1cs.Solve(w, a, b, c, opt)
	check(err)
	for i, w := range wireValues {
		fmt.Printf("wire %d: %v\n", i, w.String())
	}
}
