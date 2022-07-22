package utils

import (
	"math/rand"
)

func RandEven(nBranch int) int {
	return rand.Intn(nBranch)
}

func RandBranch(gran, existBranch uint8) uint8 {
	// Only existBranch has been probed and others have not.
	// Used in path.
	nBranch := 1 << gran
	prob := make([]int, nBranch)
	for i := 0; i < nBranch; i ++ {
		prob[i] = 1
	}
	prob[existBranch] = nBranch
	randNum := rand.Intn(nBranch * 2 - 1)
	for i := uint8(0); i < uint8(nBranch); i ++ {
		if randNum < prob[i] {
			return i
		}
		randNum -= prob[i]
	}
	return uint8(nBranch)
}

func RandBranchFloat(prob []float32) uint8 {
	// Used in children
	randNum := rand.Float32()
	for i := uint8(0); i < uint8(len(prob)); i ++ {
		if randNum < prob[i] {
			return i
		}
		randNum -= prob[i]
	}
	return uint8(len(prob)) - 1
}