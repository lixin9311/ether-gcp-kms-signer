package digest_signer

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func verifyDigest(addr common.Address, hash, sig []byte) bool {
	if len(sig) != 65 {
		return false
	} else if sig[64] != 27 && sig[64] != 28 {
		return false
	}
	sig[64] -= 27
	defer func() { sig[64] += 27 }()

	publicKey, err := crypto.Ecrecover(hash, sig)
	if err != nil {
		return false
	}

	verified := crypto.VerifySignature(publicKey, hash, sig[:len(sig)-1])
	addrA := common.BytesToAddress(crypto.Keccak256(publicKey[1:])[12:])

	return verified && addrA == addr
}
