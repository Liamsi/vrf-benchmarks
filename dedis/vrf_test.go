package vrf

import (
	"testing"

	"github.com/dedis/crypto/config"
)

func TestComplete(test *testing.T) {
	keyPair := config.NewKeyPair(suite)

	alice := []byte("alice")
	aliceVRF := Compute(alice, keyPair.Secret)
	s, t, vrf := Prove(alice, keyPair.Secret)

	if !Verify(alice, keyPair.Public, vrf, s, t) {
		test.Errorf("Failed to Compute -> Prove -> Verify ")
	}
	if !aliceVRF.Equal(vrf) {
		test.Errorf("Compute != Prove")
	}
}

func BenchmarkHashToGE(b *testing.B) {
	alice := []byte("alice")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		h1(alice)
	}
}

func BenchmarkCompute(b *testing.B) {
	kp := config.NewKeyPair(suite)
	alice := []byte("alice")
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		Compute(alice, kp.Secret)
	}
}

func BenchmarkProve(b *testing.B) {
	kp := config.NewKeyPair(suite)
	alice := []byte("alice")
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		Prove(alice, kp.Secret)
	}
}

func BenchmarkVerify(b *testing.B) {
	kp := config.NewKeyPair(suite)
	alice := []byte("alice")

	aliceVRF := Compute(alice, kp.Secret)
	s, t, vrf := Prove(alice, kp.Secret)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Verify(alice, kp.Public, vrf, s, t)
		if !aliceVRF.Equal(vrf) {
			b.Fail()
		}
	}
}
