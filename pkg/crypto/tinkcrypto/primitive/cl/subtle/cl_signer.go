/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

// CL Issuer (Signer)
type CLSigner struct {
	pubKey           *ursa.CredentialDefPubKey
	privKey          *ursa.CredentialDefPrivKey
	correctnessProof *ursa.CredentialDefKeyCorrectnessProof
}

// Creates a new instance of CLSigner with the provided privateKey.
func NewCLSigner(privKey []byte, pubKey []byte, correctnessProof []byte) (*CLSigner, error) {
	clPubKey, err := ursa.CredentialPublicKeyFromJSON(pubKey)
	if err != nil {
		return nil, err
	}
	clPrivKey, err := ursa.CredentialPrivateKeyFromJSON(privKey)
	if err != nil {
		return nil, err
	}
	clCorrecrtnessProof, err := ursa.CredentialKeyCorrectnessProofFromJSON(correctnessProof)
	if err != nil {
		return nil, err
	}
	return &CLSigner{
		pubKey:           clPubKey,
		privKey:          clPrivKey,
		correctnessProof: clCorrecrtnessProof,
	}, nil
}

// Sign
// returns:
// 		signature in []byte
//		error in case of errors
func (s *CLSigner) Sign(
	values map[string]interface{},
	blindedCredentialSecrets *ursa.BlindedCredentialSecrets,
	credentialNonce *ursa.Nonce) (*ursa.CredentialSignature, *ursa.CredentialSignatureCorrectnessProof, *ursa.Nonce, error) {
	credentialIssuanceNonce, err := ursa.NewNonce()
	if err != nil {
		return nil, nil, nil, err
	}

	builder, err := ursa.NewValueBuilder()
	if err != nil {
		return nil, nil, nil, err
	}

	for k, v := range values {
		_, enc := ursa.EncodeValue(v)
		err = builder.AddDecKnown(k, enc)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	credentialValues, err := builder.Finalize()
	if err != nil {
		return nil, nil, nil, err
	}

	signParams := ursa.NewSignatureParams()
	signParams.ProverID = "did:sov:example1"
	signParams.CredentialPubKey = s.pubKey
	signParams.CredentialPrivKey = s.privKey
	signParams.BlindedCredentialSecrets = blindedCredentialSecrets.Handle
	signParams.BlindedCredentialSecretsCorrectnessProof = blindedCredentialSecrets.CorrectnessProof
	signParams.CredentialNonce = credentialNonce
	signParams.CredentialValues = credentialValues
	signParams.CredentialIssuanceNonce = credentialIssuanceNonce

	sig, sigCorrectnessProof, err := signParams.SignCredential()
	return sig, sigCorrectnessProof, credentialIssuanceNonce, err
}

func (s *CLSigner) GetPublicKey() (*ursa.CredentialDef, error) {
	return &ursa.CredentialDef{
		PubKey:              s.pubKey,
		PrivKey:             s.privKey,
		KeyCorrectnessProof: s.correctnessProof,
	}, nil
}
