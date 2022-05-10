package digest_signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

var (
	OidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	OidSecp256k1      = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS #1 public key.
type pkcs1PublicKey struct {
	N *big.Int
	E int
}

func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

// recover R and S from KMS signature
func recoverRS(signature []byte) (r *big.Int, s *big.Int, err error) {
	r, s = &big.Int{}, &big.Int{}
	var inner cryptobyte.String
	input := cryptobyte.String(signature)
	if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid sig")
	}
	// Google may have already encured that the signature is valid, but we
	// can't assume that.
	if s.Cmp(secp256k1halfN) > 0 {
		s = s.Sub(secp256k1N, s)
	}
	return r, s, nil
}

func pemToPubkey(pemString string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	derBytes := block.Bytes
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		if _, err := asn1.Unmarshal(derBytes, &pkcs1PublicKey{}); err == nil {
			return nil, errors.New("x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")
		}
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}

	if !pki.Algorithm.Algorithm.Equal(OidPublicKeyECDSA) {
		return nil, errors.New("x509: not a ECDSA public key")
	}

	der := cryptobyte.String(pki.PublicKey.RightAlign())
	paramsDer := cryptobyte.String(pki.Algorithm.Parameters.FullBytes)
	namedCurveOID := new(asn1.ObjectIdentifier)
	if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
		return nil, errors.New("x509: invalid ECDSA parameters")
	}

	if !namedCurveOID.Equal(OidSecp256k1) {
		return nil, errors.New("x509: not a secp256k1 curve")
	}
	curve := crypto.S256()

	x, y := elliptic.Unmarshal(curve, der)
	if x == nil {
		return nil, errors.New("x509: failed to unmarshal secp256k1 curve point")
	}
	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return pub, nil
}
