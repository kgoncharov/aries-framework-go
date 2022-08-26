/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/cl"
)

type rawRequest struct {
	ProverDid                 string          `json:"prover_did"`
	CredDefId                 string          `json:"cred_def_id"`
	BlindedMs                 json.RawMessage `json:"blinded_ms"`
	BlindedMsCorrectnessProof json.RawMessage `json:"blinded_ms_correctness_proof"`
	Nonce                     string          `json:"nonce"`
}

type CredentialRequest struct {
	ProverDid                 DID
	CredDefId                 CredDefID
	BlindedMs                 []byte
	BlindedMsCorrectnessProof []byte
	Nonce                     string
}

func (d *CredentialRequest) ForCL() (*cl.CredentialRequest, error) {
	return &cl.CredentialRequest{
		ProverID: string(d.ProverDid),
		BlindedCredentialSecrets: &cl.BlindedCredentialSecrets{
			Handle:           d.BlindedMs,
			CorrectnessProof: d.BlindedMsCorrectnessProof,
		},
		Nonce: []byte(d.Nonce),
	}, nil
}

func (d *CredentialRequest) IssueFor(issuer cl.Issuer, values map[string]interface{}) (*cl.Credential, error) {
	// TODO: check how and where to get cred offer on the issuer side
	var clOffer *cl.CredentialOffer

	clReq, err := d.ForCL()
	if err != nil {
		return nil, err
	}

	return issuer.IssueCredential(values, clReq, clOffer)
}

// ParseCredentialRequest parses CredentialRequest from base64 rfc0592 indy cred-req.
func ParseCredentialRequest(base64Data string) (*CredentialRequest, error) {
	decoded, err := decodeBase64(base64Data)
	if err != nil {
		return nil, fmt.Errorf("decode : %w", err)
	}

	var raw rawRequest

	err = json.Unmarshal(decoded, &raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal request: %w", err)
	}

	data, err := newRequest(&raw)
	if err != nil {
		return nil, fmt.Errorf("build new request: %w", err)
	}

	err = validateRequest(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func newRequest(raw *rawRequest) (*CredentialRequest, error) {
	return &CredentialRequest{
		ProverDid:                 DID(raw.ProverDid),
		CredDefId:                 CredDefID(raw.CredDefId),
		Nonce:                     raw.Nonce,
		BlindedMs:                 raw.BlindedMs,
		BlindedMsCorrectnessProof: raw.BlindedMsCorrectnessProof,
	}, nil
}

func validateRequest(data *CredentialRequest) error {
	return nil
}
