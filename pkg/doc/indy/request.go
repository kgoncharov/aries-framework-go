/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"encoding/json"
	"fmt"
)

type rawRequest struct {
	ProverDID                 string          `json:"prover_did"`
	CredDefID                 string          `json:"cred_def_id"`
	BlindedMs                 json.RawMessage `json:"blinded_ms"`
	BlindedMsCorrectnessProof json.RawMessage `json:"blinded_ms_correctness_proof"`
	Nonce                     string          `json:"nonce"`
}

// CredentialRequest contains data for rfc0592 indy cred request.
type CredentialRequest struct {
	ProverDID                 DID
	CredDefID                 CredDefID
	BlindedMs                 []byte
	BlindedMsCorrectnessProof []byte
	Nonce                     string
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
		ProverDID:                 DID(raw.ProverDID),
		CredDefID:                 CredDefID(raw.CredDefID),
		Nonce:                     raw.Nonce,
		BlindedMs:                 raw.BlindedMs,
		BlindedMsCorrectnessProof: raw.BlindedMsCorrectnessProof,
	}, nil
}

func validateRequest(data *CredentialRequest) error {
	return nil
}
