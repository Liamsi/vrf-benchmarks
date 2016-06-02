package main

import (
	"github.com/pkg/profile"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
)

var suite = edwards.NewAES128SHA256Ed25519(true)

func main() {
	defer profile.Start(profile.CPUProfile).Stop()
	m := []byte("alice")
	P := suite.Point()
	Ph := P.(abstract.Hiding)
	hash := suite.Hash()
	hash.Write(m)
	hmb := hash.Sum(nil)

	Ph.HideDecode(hmb)
}