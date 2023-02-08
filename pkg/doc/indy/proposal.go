/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"encoding/json"
	"fmt"
)

type rawProposal struct {
	SchemaIssuerDID string `json:"schema_issuer_did,omitempty"`
	SchemaName      string `json:"schema_name,omitempty"`
	SchemaVersion   string `json:"schema_version,omitempty"`
	SchemaID        string `json:"schema_id,omitempty"`
	IssuerDID       string `json:"issuer_did,omitempty"`
	CredDefID       string `json:"cred_def_id,omitempty"`
}

// CredentialProposal contains data for rfc0592 indy cred proposal.
type CredentialProposal struct {
	SchemaIssuerDID DID
	SchemaName      string
	SchemaVersion   string
	SchemaID        SchemaID
	IssuerDID       DID
	CredDefID       CredDefID
}

// ParseCredentialProposal parses CredentialProposal from base64 rfc0592 indy cred-filter.
func ParseCredentialProposal(base64Data string) (*CredentialProposal, error) {
	decoded, err := decodeBase64(base64Data)
	if err != nil {
		return nil, fmt.Errorf("decode : %w", err)
	}

	var raw rawProposal

	err = json.Unmarshal(decoded, &raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal proposal: %w", err)
	}

	data, err := newProposal(&raw)
	if err != nil {
		return nil, fmt.Errorf("build new proposal: %w", err)
	}

	err = validateProposal(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func newProposal(raw *rawProposal) (*CredentialProposal, error) {
	return &CredentialProposal{
		SchemaIssuerDID: DID(raw.SchemaIssuerDID),
		SchemaName:      raw.SchemaName,
		SchemaVersion:   raw.SchemaVersion,
		SchemaID:        SchemaID(raw.SchemaID),
		IssuerDID:       DID(raw.IssuerDID),
		CredDefID:       CredDefID(raw.CredDefID),
	}, nil
}

func validateProposal(data *CredentialProposal) error {
	return nil
}
