package wallet_signer

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/lixin9311/ether-gcp-kms-signer/digest_signer"
)

var _ accounts.Wallet = (*Signer)(nil)

type Signer struct {
	kmsSigner *digest_signer.KMSSigner
	timeout   time.Duration
}

// URL retrieves the canonical path under which this wallet is reachable. It is
// used by upper layers to define a sorting order over all wallets from multiple
// backends.
func (s *Signer) URL() accounts.URL {
	return accounts.URL{
		Scheme: "kmssigner",
		Path:   s.kmsSigner.ResourcePath(),
	}
}

// Status returns a textual status to aid the user in the current state of the
// wallet. It also returns an error indicating any failure the wallet might have
// encountered.
func (s *Signer) Status() (string, error) {
	state := s.kmsSigner.GetConnectionStatus()
	if state == "INVALID_STATE" {
		return "", fmt.Errorf("invalid state")
	}
	return state, nil
}

// Open initializes access to a wallet instance. It is not meant to unlock or
// decrypt account keys, rather simply to establish a connection to hardware
// wallets and/or to access derivation seeds.
//
// The passphrase parameter may or may not be used by the implementation of a
// particular wallet instance. The reason there is no passwordless open method
// is to strive towards a uniform wallet handling, oblivious to the different
// backend providers.
//
// Please note, if you open a wallet, you must close it to release any allocated
// resources (especially important when working with hardware wallets).
func (s *Signer) Open(passphrase string) error {
	return fmt.Errorf("operation not supported on kms signers")
}

// Close releases any resources held by an open wallet instance.
func (s *Signer) Close() error {
	return s.kmsSigner.Close()
}

// Accounts retrieves the list of signing accounts the wallet is currently aware
// of. For hierarchical deterministic wallets, the list will not be exhaustive,
// rather only contain the accounts explicitly pinned during account derivation.
func (s *Signer) Accounts() []accounts.Account {
	keys := s.kmsSigner.ListVersionedKeys()
	result := make([]accounts.Account, 0, len(keys))
	for addr, key := range keys {
		result = append(result,
			accounts.Account{
				Address: addr,
				URL:     accounts.URL{Scheme: "kmssigner", Path: key},
			})
	}
	return result
}

// Contains returns whether an account is part of this particular wallet or not.
func (s *Signer) Contains(account accounts.Account) bool {
	return s.kmsSigner.HasAddress(account.Address)
}

// Derive attempts to explicitly derive a hierarchical deterministic account at
// the specified derivation path. If requested, the derived account will be added
// to the wallet's tracked account list.
func (s *Signer) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	return accounts.Account{}, fmt.Errorf("operation not supported on kms signers")
}

// SelfDerive sets a base account derivation path from which the wallet attempts
// to discover non zero accounts and automatically add them to list of tracked
// accounts.
//
// Note, self derivation will increment the last component of the specified path
// opposed to descending into a child path to allow discovering accounts starting
// from non zero components.
//
// Some hardware wallets switched derivation paths through their evolution, so
// this method supports providing multiple bases to discover old user accounts
// too. Only the last base will be used to derive the next empty account.
//
// You can disable automatic account discovery by calling SelfDerive with a nil
// chain state reader.
func (s *Signer) SelfDerive(bases []accounts.DerivationPath, chain ethereum.ChainStateReader) {
	log.Error("operation SelfDerive not supported on kms signers")
}

// SignData requests the wallet to sign the hash of the given data
// It looks up the account specified either solely via its address contained within,
// or optionally with the aid of any location metadata from the embedded URL field.
//
// If the wallet requires additional authentication to sign the request (e.g.
// a password to decrypt the account, or a PIN code to verify the transaction),
// an AuthNeededError instance will be returned, containing infos for the user
// about which fields or actions are needed. The user may retry by providing
// the needed details via SignDataWithPassphrase, or by other means (e.g. unlock
// the account in a keystore).
func (s *Signer) SignData(account accounts.Account, mimeType string, data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	hashed := crypto.Keccak256(data)
	res, err := s.kmsSigner.SignDigest(ctx, account.Address, hashed)
	if err != nil {
		return nil, err
	}
	// If V is on 27/28-form, convert to 0/1 for Clique
	if mimeType == accounts.MimetypeClique && (res[64] == 27 || res[64] == 28) {
		res[64] -= 27 // Transform V from 27/28 to 0/1 for Clique use
	}
	return res, nil
}

// SignDataWithPassphrase is identical to SignData, but also takes a password
// NOTE: there's a chance that an erroneous call might mistake the two strings, and
// supply password in the mimetype field, or vice versa. Thus, an implementation
// should never echo the mimetype or return the mimetype in the error-response
func (s *Signer) SignDataWithPassphrase(account accounts.Account, passphrase, mimeType string, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("password-operations not supported on kms signers")
}

// SignText requests the wallet to sign the hash of a given piece of data, prefixed
// by the Ethereum prefix scheme
// It looks up the account specified either solely via its address contained within,
// or optionally with the aid of any location metadata from the embedded URL field.
//
// If the wallet requires additional authentication to sign the request (e.g.
// a password to decrypt the account, or a PIN code to verify the transaction),
// an AuthNeededError instance will be returned, containing infos for the user
// about which fields or actions are needed. The user may retry by providing
// the needed details via SignTextWithPassphrase, or by other means (e.g. unlock
// the account in a keystore).
//
// This method should return the signature in 'canonical' format, with v 0 or 1.
func (s *Signer) SignText(account accounts.Account, text []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	hashed := accounts.TextHash(text)
	res, err := s.kmsSigner.SignDigest(ctx, account.Address, hashed)
	if err != nil {
		return nil, err
	}
	if res[64] == 27 || res[64] == 28 {
		res[64] -= 27 // Transform V from Ethereum-legacy to 0/1
	}
	return res, nil
}

// SignTextWithPassphrase is identical to Signtext, but also takes a password
func (s *Signer) SignTextWithPassphrase(account accounts.Account, passphrase string, hash []byte) ([]byte, error) {
	return []byte{}, fmt.Errorf("password-operations not supported on kms signers")
}

// SignTx requests the wallet to sign the given transaction.
//
// It looks up the account specified either solely via its address contained within,
// or optionally with the aid of any location metadata from the embedded URL field.
//
// If the wallet requires additional authentication to sign the request (e.g.
// a password to decrypt the account, or a PIN code to verify the transaction),
// an AuthNeededError instance will be returned, containing infos for the user
// about which fields or actions are needed. The user may retry by providing
// the needed details via SignTxWithPassphrase, or by other means (e.g. unlock
// the account in a keystore).
func (s *Signer) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	signer := types.LatestSignerForChainID(chainID)
	h := signer.Hash(tx)
	res, err := s.kmsSigner.SignDigest(ctx, account.Address, h[:])
	if err != nil {
		return nil, err
	}
	if res[64] == 27 || res[64] == 28 {
		res[64] -= 27 // Transform V from Ethereum-legacy to 0/1
	}
	return tx.WithSignature(signer, res)
}

// SignTxWithPassphrase is identical to SignTx, but also takes a password
func (s *Signer) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return nil, fmt.Errorf("password-operations not supported on kms signers")
}
