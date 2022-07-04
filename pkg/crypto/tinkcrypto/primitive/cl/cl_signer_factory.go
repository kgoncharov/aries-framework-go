package cl

import (
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	clapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/api"
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

// NewSigner returns a CL Signer primitive from the given keyset handle.
func NewSigner(h *keyset.Handle) (clapi.Signer, error) {
	return NewSignerWithKeyManager(h, nil)
}

// NewSignerWithKeyManager returns a BBS Signer primitive from the given keyset handle and custom key manager.
func NewSignerWithKeyManager(h *keyset.Handle, km registry.KeyManager) (clapi.Signer, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("cl_sign_factory: cannot obtain primitive set: %w", err)
	}

	return newWrappedSigner(ps)
}

// wrappedSigner is a BBS Signer implementation that uses the underlying primitive set for bbs signing.
type wrappedSigner struct {
	ps *primitiveset.PrimitiveSet
}

// newWrappedSigner constructor creates a new wrappedSigner and checks primitives in ps are all of BBS Signer type.
func newWrappedSigner(ps *primitiveset.PrimitiveSet) (*wrappedSigner, error) {
	if _, ok := (ps.Primary.Primitive).(clapi.Signer); !ok {
		return nil, fmt.Errorf("cl_signer_factory: not a CL Signer primitive")
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(clapi.Signer); !ok {
				return nil, fmt.Errorf("cl_signer_factory: not a CL Signer primitive")
			}
		}
	}

	ret := new(wrappedSigner)
	ret.ps = ps

	return ret, nil
}

// Sign signs the given messages and returns the signature concatenated with the identifier of the primary primitive.
func (ws *wrappedSigner) Sign(values map[string]interface{},
	blindedCredentialSecrets *ursa.BlindedCredentialSecrets,
	credentialNonce *ursa.Nonce) (*ursa.CredentialSignature, *ursa.CredentialSignatureCorrectnessProof, *ursa.Nonce, error) {
	primary := ws.ps.Primary

	signer, ok := (primary.Primitive).(clapi.Signer)
	if !ok {
		return nil, nil, nil, fmt.Errorf("cl_signer_factory: not a CL Signer primitive")
	}

	return signer.Sign(values, blindedCredentialSecrets, credentialNonce)
}

func (ws *wrappedSigner) GetPublicKey() (*ursa.CredentialDef, error) {
	primary := ws.ps.Primary

	signer, ok := (primary.Primitive).(clapi.Signer)
	if !ok {
		return nil, fmt.Errorf("cl_signer_factory: not a CL Signer primitive")
	}

	return signer.GetPublicKey()
}
