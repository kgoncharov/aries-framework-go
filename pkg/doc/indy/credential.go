/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"encoding/json"
	"fmt"
)

type rawCredential struct {
	SchemaID                  string          `json:"schema_id,omitempty"`
	CredDefID                 string          `json:"cred_def_id"`
	Values                    CredValues      `json:"values"`
	Signature                 json.RawMessage `json:"signature"`
	SignatureCorrectnessProof json.RawMessage `json:"signature_correctness_proof"`
}

// Credential contains data for rfc0592 indy cred.
type Credential struct {
	SchemaID                  SchemaID
	CredDefID                 CredDefID
	Values                    CredValues
	Signature                 []byte
	SignatureCorrectnessProof []byte
}

// ParseCredential parses Credential from base64 rfc0592 indy cred.
func ParseCredential(base64Data string) (*Credential, error) {
	decoded, err := decodeBase64(base64Data)
	if err != nil {
		return nil, fmt.Errorf("decode : %w", err)
	}

	var raw rawCredential

	err = json.Unmarshal(decoded, &raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal credential: %w", err)
	}

	data, err := newCredential(&raw)
	if err != nil {
		return nil, fmt.Errorf("build new credential: %w", err)
	}

	err = validateCredential(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func newCredential(raw *rawCredential) (*Credential, error) {
	return &Credential{
		SchemaID:                  SchemaID(raw.SchemaID),
		CredDefID:                 CredDefID(raw.CredDefID),
		Values:                    raw.Values,
		Signature:                 raw.Signature,
		SignatureCorrectnessProof: raw.SignatureCorrectnessProof,
	}, nil
}

func validateCredential(data *Credential) error {
	return nil
}
