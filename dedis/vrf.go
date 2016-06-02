package vrf

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	// optimized edwards implementation (lacking full implementation of the elligator map)
	// "github.com/dedis/crypto/edwards/ed25519"
	"github.com/dedis/crypto/random"
)

var suite = edwards.NewAES128SHA256Ed25519(true)
//var suite = ed25519.NewAES128SHA256Ed25519(true)

func Compute(m []byte, sk abstract.Secret) abstract.Point {
	// H(m)^k
	P := h1(m)
	P = P.Mul(P, sk)

	return P
}

// Prove_x(n) = tuple(s=h(n, g^r, H(n)^r), t=r-s*x, vrf=H(n)^x)
func Prove(m []byte, k abstract.Secret) (s abstract.Secret, t abstract.Secret, vrf abstract.Point) {
	r := suite.Secret().Pick(random.Stream)
	g := suite.Point().Base()

	h := h1(m)
	// copy h into hr
	hr := suite.Point().Add(suite.Point().Null(), h)
	// h = h1(m)^k
	h = h.Mul(h, k)
	// hr = h^r
	hr = hr.Mul(hr, r)
	// s = h2(m, g^r, h^r)
	s = h2(m, g.Mul(g, r), hr)

	// vrf = h1(m)^k
	vrf = h

	t = suite.Secret().Mul(s, k) // s*k
	t = t.Sub(r, t) // r - s*k
	return
}

// Verify returns true iff vrf=Compute(m, sk) for the sk that corresponds to pk.
// vrf won't be modified
func Verify(m []byte, pk, vrf abstract.Point, s, t abstract.Secret) bool {
	g := suite.Point().Base()
	gt := g.Mul(g, t)
	// aux1 = g^t*G^s
	G := pk
	aux1 := gt.Add(gt, G.Mul(G, s))

	h1m := h1(m)
	h1mt := h1m.Mul(h1m, t)
	// XXX expensive (?) copy of vrf ...
	vrfk := suite.Point().Add(suite.Point().Null(), vrf)
	vrfms := vrfk.Mul(vrfk, s)

	// aux2 = h1(m)^t*VRF_k(m)^s
	aux2 := h1mt.Add(h1mt, vrfms)
	s2 := h2(m, aux1, aux2)
	return s.Equal(s2)
}

func hashToCurve(m []byte) abstract.Point {
	h := suite.Hash()
	defer h.Reset()
	h.Write(m)
	hmb := h.Sum(nil)
	// naive approach: ~0 times slower then elligator map
	P, _ := suite.Point().Pick(hmb, suite.Cipher(hmb))


	return P
}

func hashToCurveElligator(m []byte) abstract.Point {
	P := suite.Point()
	Ph := P.(abstract.Hiding)
	hash := suite.Hash()
	hash.Write(m)
	hmb := hash.Sum(nil)

	Ph.HideDecode(hmb)
	return  P
}

func h1(m []byte) abstract.Point {
	return hashToCurveElligator(m)
	// return hashToCurve(m)
}

func h2(m []byte, gr abstract.Point, hr abstract.Point) abstract.Secret {
	hash := suite.Hash()
	hash.Write(m)
	hmb := hash.Sum(nil)

	// use the messages hash as a Cipher/seed and pick a secret
	return suite.Secret().Pick(suite.Cipher(hmb))
}