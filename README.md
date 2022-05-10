# ether-gcp-kms-signer

[![API Reference](
https://camo.githubusercontent.com/915b7be44ada53c290eb157634330494ebe3e30a/68747470733a2f2f676f646f632e6f72672f6769746875622e636f6d2f676f6c616e672f6764646f3f7374617475732e737667
)](https://pkg.go.dev/github.com/lixin9311/ether-gcp-kms-signer?tab=doc)

Utility to sign Ethereum compatible signature with Google Cloud KMS.

```shell
go get -u github.com/lixin9311/ether-gcp-kms-signer
```

## How does it work?

This project is inspired by [ethers-gcp-kms-signer](https://github.com/openlawteam/ethers-gcp-kms-signer).

GCP KMS won't and cannot check if the given digest is a `SHA256` one instead of other hashes without providing the original message.

So we can trick the KMS to sign a message with a `Keccak256` digest.

**Please note there are some differences with the standard eth behavior:**

Standard eth library will generate the same stable signature for the same message by using a hash as the nonce.

Unlike most eth libs, each time KMS will generate a different signature for the same message.
Since it will use a safe random number generator to generate the nonce, it should be safe, and compatible with other eth libraries.

## How to use

First, you need to create a [`ec-sign-secp256k1-sha256`](https://cloud.google.com/kms/docs/algorithms#elliptic_curve_signing_algorithms) private key in Google Cloud KMS, follow the documentation here: <https://cloud.google.com/kms/docs/creating-asymmetric-keys>

Or, you can [bring your own private key](https://cloud.google.com/kms/docs/importing-a-key) to it, by using the utils in this project to generate the correct [der format key](https://cloud.google.com/kms/docs/formatting-keys-for-import#formatting_asymmetric_keys) from HEX format.

Also, you can create/import multiple private keys to the same Google Cloud KMS key, by utilizing the key versioning feature.

If you provide an empty KeyVersion upon initializing the digest signer, it will try to fetch all available key versions, and treat them as different wallet - private key pairs.

## Usage

Check out the code, it is simple.

`wallet_signer` implements the [`Wallet`](https://pkg.go.dev/github.com/ethereum/go-ethereum/accounts#Wallet) interface, and can be used as a wallet for eth libraries.

Or you can use `digest_singer` directly to sign a hashed data.
