package main

import (
	"bufio"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/lixin9311/ether-gcp-kms-signer/digest_signer"
)

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

var (
	output = flag.String("o", "key.der", "output file")
)

func main() {
	flag.Parse()

	reader := bufio.NewReader(os.Stdin)
	hexkey, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		log.Fatalf("failed to read hex key: %v\n", err)
	}
	hexkey = strings.TrimSpace(hexkey)
	pk, err := crypto.HexToECDSA(hexkey)
	if err != nil {
		log.Fatalf("failed to parse hex key: %v\n", err)
	}

	var privKey pkcs8
	oidBytes, err := asn1.Marshal(digest_signer.OidSecp256k1)
	if err != nil {
		log.Fatalf("x509: failed to marshal curve OID: %v\n", err)
	}
	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: digest_signer.OidPublicKeyECDSA,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}

	privateKey := make([]byte, (pk.Curve.Params().N.BitLen()+7)/8)
	privKey.PrivateKey, err = asn1.Marshal(ecPrivateKey{
		Version:    1,
		PrivateKey: pk.D.FillBytes(privateKey),
		PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(pk.Curve, pk.X, pk.Y)},
	})
	if err != nil {
		log.Fatalf("x509: failed to marshal private key: %v\n", err)
	}
	bytes, err := asn1.Marshal(privKey)
	if err != nil {
		log.Fatalf("x509: failed to marshal der: %v\n", err)
	}
	f, err := os.Create(*output)
	if err != nil {
		log.Fatalf("failed to create output file: %v\n", err)
	}
	if _, err := f.Write(bytes); err != nil {
		log.Fatalf("failed to write to output file: %v\n", err)
	}
	fmt.Println("Successfully wrote key to", *output)

}
