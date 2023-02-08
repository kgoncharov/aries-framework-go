/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cl

import "github.com/hyperledger/aries-framework-go/pkg/doc/indy"

// FromIndyCredential converts indy Credential into CL Credential format.
func FromIndyCredential(cred *indy.Credential) (*Credential, error) {
	return &Credential{
		Signature: cred.Signature,
		Values:    indy.RawCredValues(cred.Values),
		SigProof:  cred.SignatureCorrectnessProof,
	}, nil
}

// FromIndyOffer converts indy CredentialOffer into CL CredentialOffer format.
func FromIndyOffer(offer *indy.CredentialOffer) (*CredentialOffer, error) {
	return &CredentialOffer{Nonce: []byte(offer.Nonce)}, nil
}

// FromIndyRequest converts indy CredentialRequest into CL CredentialRequest format.
func FromIndyRequest(req *indy.CredentialRequest) (*CredentialRequest, error) {
	return &CredentialRequest{
		ProverID: string(req.ProverDID),
		BlindedCredentialSecrets: &BlindedCredentialSecrets{
			Handle:           req.BlindedMs,
			CorrectnessProof: req.BlindedMsCorrectnessProof,
		},
		Nonce: []byte(req.Nonce),
	}, nil
}
