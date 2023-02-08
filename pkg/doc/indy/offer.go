/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"encoding/json"
	"fmt"
)

type rawOffer struct {
	SchemaID            string          `json:"schema_id,omitempty"`
	CredDefID           string          `json:"cred_def_id"`
	Nonce               string          `json:"nonce"`
	KeyCorrectnessProof json.RawMessage `json:"key_correctness_proof"`
}

// CredentialOffer contains data for rfc0592 indy cred offer.
type CredentialOffer struct {
	SchemaID            SchemaID
	CredDefID           CredDefID
	Nonce               string
	KeyCorrectnessProof []byte
}

// ParseCredentialOffer parses CredentialOffer from base64 rfc0592 indy cred-abstract.
func ParseCredentialOffer(base64Data string) (*CredentialOffer, error) {
	decoded, err := decodeBase64(base64Data)
	if err != nil {
		return nil, fmt.Errorf("decode : %w", err)
	}

	var raw rawOffer

	err = json.Unmarshal(decoded, &raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal offer: %w", err)
	}

	data, err := newOffer(&raw)
	if err != nil {
		return nil, fmt.Errorf("build new offer: %w", err)
	}

	err = validateOffer(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func newOffer(raw *rawOffer) (*CredentialOffer, error) {
	// TODO: ensure every mandatory field was correctly parsed
	return &CredentialOffer{
		SchemaID:            SchemaID(raw.SchemaID),
		CredDefID:           CredDefID(raw.CredDefID),
		Nonce:               raw.Nonce,
		KeyCorrectnessProof: raw.KeyCorrectnessProof,
	}, nil
}

func validateOffer(data *CredentialOffer) error {
	// TODO: add validation if needed
	return nil
}
