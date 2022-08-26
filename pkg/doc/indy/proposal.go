/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"fmt"
	"encoding/json"
)

type rawProposal struct {
	SchemaIssuerDid string `json:"schema_issuer_did,omitempty"`
	SchemaName      string `json:"schema_name,omitempty"`
	SchemaVersion   string `json:"schema_version,omitempty"`
	SchemaId        string `json:"schema_id,omitempty"`
	IssuerDid       string `json:"issuer_did,omitempty"`
	CredDefId       string `json:"cred_def_id,omitempty"`
}

type CredentialProposal struct {
	SchemaIssuerDid DID
	SchemaName      string
	SchemaVersion   string
	SchemaId        SchemaID
	IssuerDid       DID
	CredDefId       CredDefID
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
		SchemaIssuerDid: DID(raw.SchemaIssuerDid),
		SchemaName:      raw.SchemaName,
		SchemaVersion:   raw.SchemaVersion,
		SchemaId:        SchemaID(raw.SchemaId),
		IssuerDid:       DID(raw.IssuerDid),
		CredDefId:       CredDefID(raw.CredDefId),
	}, nil
}

func validateProposal(data *CredentialProposal) error {
	return nil
}
