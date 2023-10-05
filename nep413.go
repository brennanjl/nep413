package nep413

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
	borsch "github.com/near/borsh-go"
)

// nep413SignatureRequest is the response from an NEP-413 signature.
// it implements the encoding.BinaryMarshaler and encoding.BinaryUnmarshaler interfaces.
// it utilizes borsch for deterministic serialization
type Nep413SignatureResponse struct {
	// AccountId is the account id that signed the message
	AccountId string
	// Signature is the base64 encoded signature
	Signature string
	// PublicKey is the hex encoded public key, prepending with NEAR's "ed25519"
	// ex: "ed25519:8HnzkUaX21h99idPghFajoV3JZvy3SmJ4mqVwSVfLByg"
	PublicKey string
}

// PubKey returns the ed25519 public key
func (n *Nep413SignatureResponse) PubKey() (ed25519.PublicKey, error) {
	// NEAR's public keys are in the format ed25519:8HnzkUaX21h99idPghFajoV3JZvy3SmJ4mqVwSVfLByg
	// where the first part is the algorithm, and the second part is the base58 encoded public key
	splitKey := strings.Split(n.PublicKey, ":")
	if len(splitKey) != 2 {
		return nil, errors.New("invalid public key format, expected ed25519:base58_encoded_public_key")
	}

	// decode the public key
	pubkeyBytes, err := base58.Decode(splitKey[1])
	if err != nil {
		return nil, err
	}

	if len(pubkeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length, expected %d, got %d", ed25519.PublicKeySize, len(pubkeyBytes))
	}

	return pubkeyBytes, nil
}

func (n Nep413SignatureResponse) MarshalBinary() ([]byte, error) {
	return borsch.Serialize(n)
}

func (n *Nep413SignatureResponse) UnmarshalBinary(data []byte) error {
	return borsch.Deserialize(n, data)
}

// Nep413Message is the message sent to the NEP-413 signer.
// it implements the encoding.BinaryMarshaler and encoding.BinaryUnmarshaler interfaces.
// it utilizes borsch for deterministic serialization
type Nep413Message struct {
	// Tag is some NEAR specific thing that is not really explained anywhere,
	// but should always be the number 2^31+413, or 2147484061
	// https://github.com/near/NEPs/blob/master/neps/nep-0413.md#example
	Tag uint32

	// Message is the plaintext message
	Message string

	// Nonce is the 32 byte nonce of the message
	Nonce [32]byte

	// Recipient is the string identifier of the recipient (e.g. satoshi.near)
	Recipient string

	// CallbackUrl is the url to call when the signature is ready
	CallbackUrl string
}

// Verify verifies an NEP-413 signature.
// It is based on the implementation found here: https://github.com/gagdiez/near-login/blob/3c0ad7d6587c835202b06d36afbde50ee6c6fec9/tests/authentication/wallet.ts#L60
func Verify(msg *Nep413Message, res *Nep413SignatureResponse) error {
	msg.Tag = 2147484061

	// cast the sender to an ed25519 public key
	publicKey, err := res.PubKey()
	if err != nil {
		return err
	}

	// decode the signature
	decodedSignature, err := base64.StdEncoding.DecodeString(res.Signature)
	if err != nil {
		return err
	}

	// serialize payload
	// we dereference pointer since go-borsch is bugged
	// and does not correctly handle pointers
	serializedPayload, err := borsch.Serialize(*msg)
	if err != nil {
		return err
	}

	fmt.Println("serializedPayload", serializedPayload)

	// hash the payload
	hashedPayload := sha256.Sum256(serializedPayload)

	if !ed25519.Verify(publicKey, hashedPayload[:], decodedSignature) {
		return errors.New("signature verification failed")
	}

	return nil
}
