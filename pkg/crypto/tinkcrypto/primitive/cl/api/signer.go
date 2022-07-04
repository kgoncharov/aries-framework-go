/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

// Signer is the signing interface primitive for CL signatures used by Tink.
type Signer interface {
	// Sign will create a CL signature by the Issuer
	Sign(values map[string]interface{},
		blindedCredentialSecrets *ursa.BlindedCredentialSecrets,
		credentialNonce *ursa.Nonce) (*ursa.CredentialSignature, *ursa.CredentialSignatureCorrectnessProof, *ursa.Nonce, error)
	GetPublicKey() (*ursa.CredentialDef, error)
}
