package digest_signer

import (
	"context"
	"errors"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"golang.org/x/oauth2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type KMSCred struct {
	ProjectID   string
	Location    string
	KeyRing     string
	Key         string
	KeyVersion  string             // (Optional) if you want to use a specific key version
	TokenSource oauth2.TokenSource // (Optional) if you want to use a custom token source, e.g. a service account
}

func (c *KMSCred) keyname() string {
	return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", c.ProjectID, c.Location, c.KeyRing, c.Key)
}

func (c *KMSCred) keyversion() string {
	return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", c.ProjectID, c.Location, c.KeyRing, c.Key, c.KeyVersion)
}

type KMSSigner struct {
	client           *kms.KeyManagementClient
	resourcePath     string
	addressVerionMap map[common.Address]string
}

func NewKMSSigner(ctx context.Context, cfg *KMSCred) (*KMSSigner, error) {
	client, err := kms.NewKeyManagementClient(ctx, option.WithTokenSource(cfg.TokenSource))
	if err != nil {
		return nil, fmt.Errorf("failed to create kms client: %w", err)
	}
	s := &KMSSigner{
		client:           client,
		addressVerionMap: map[common.Address]string{},
	}
	if err := s.loadAddress(ctx, cfg); err != nil {
		return nil, fmt.Errorf("failed to get addresses: %w", err)
	}
	if len(s.addressVerionMap) == 0 {
		return nil, errors.New("no valid eth private key found")
	}
	return s, nil
}

func (s *KMSSigner) HasAddress(addr common.Address) bool {
	_, ok := s.addressVerionMap[addr]
	return ok
}

func (s *KMSSigner) ResourcePath() string {
	return s.resourcePath
}

func (s *KMSSigner) GetConnectionStatus() string {
	return s.client.Connection().GetState().String()
}

func (k *KMSSigner) GetAddresses() []common.Address {
	addresses := make([]common.Address, 0, len(k.addressVerionMap))
	for k := range k.addressVerionMap {
		addresses = append(addresses, k)
	}
	return addresses
}

func (k *KMSSigner) ListVersionedKeys() map[common.Address]string {
	result := map[common.Address]string{}
	for k, v := range k.addressVerionMap {
		result[k] = v
	}
	return result
}

func (k *KMSSigner) SignDigest(ctx context.Context, address common.Address, digest []byte) ([]byte, error) {
	keyVersion, ok := k.addressVerionMap[address]
	if !ok {
		return nil, fmt.Errorf("no eth private key found for address %s", address)
	}

	digestCRC32C := crc32c(digest)
	req := &kmspb.AsymmetricSignRequest{
		Name: keyVersion,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		},
		DigestCrc32C: wrapperspb.Int64(int64(digestCRC32C)),
	}

	// Call the API.
	result, err := k.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, err
	}
	if !result.VerifiedDigestCrc32C {
		return nil, fmt.Errorf("AsymmetricSign: request corrupted in-transit")
	}

	if int64(crc32c(result.Signature)) != result.SignatureCrc32C.Value {
		return nil, fmt.Errorf("AsymmetricSign: response corrupted in-transit")
	}

	// recover R and S from the signature
	r, s, err := recoverRS(result.Signature)
	if err != nil {
		return nil, err
	}

	// Reconstruct the eth signature R || S || V
	sig := make([]byte, 65)
	copy(sig[:32], r.Bytes())
	copy(sig[32:64], s.Bytes())
	sig[64] = 0x1b

	// TODO: is ther a better way to determine the value of V?
	if !verifyDigest(address, digest, sig) {
		sig[64] += 1
		if !verifyDigest(address, digest, sig) {
			return nil, fmt.Errorf("AsymmetricSign: signature failed, unable to determine V")
		}
	}

	return sig, nil
}

func (l *KMSSigner) Close() error {
	return l.client.Close()
}

func (k *KMSSigner) loadAddress(ctx context.Context, cfg *KMSCred) error {
	if cfg.KeyVersion == "" {
		keyName := cfg.keyname()
		k.resourcePath = keyName
		it := k.client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
			Parent: keyName,
			Filter: "state=ENABLED AND algorithm=EC_SIGN_SECP256K1_SHA256",
		})
		for {
			resp, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return err
			}
			if err := k.setAddress(ctx, resp.GetName()); err != nil {
				return err
			}
		}
	} else {
		k.resourcePath = cfg.keyversion()
		return k.setAddress(ctx, cfg.keyversion())
	}
	return nil
}

func (k *KMSSigner) setAddress(ctx context.Context, key string) error {
	resp, err := k.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: key,
	})
	if err != nil {
		return err
	}
	pk, err := pemToPubkey(resp.Pem)
	if err != nil {
		return err
	}
	k.addressVerionMap[crypto.PubkeyToAddress(*pk)] = key
	return nil
}
