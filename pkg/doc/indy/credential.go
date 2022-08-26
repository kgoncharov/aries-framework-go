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

type rawCredential struct {
	SchemaId  string `json:"schema_id,omitempty"`
	CredDefId string `json:"cred_def_id"`
	// TODO: change to CredValues type and fix parsing and ForCL conversion
	Values                    map[string]interface{} `json:"values"`
	Signature                 json.RawMessage        `json:"signature"`
	SignatureCorrectnessProof json.RawMessage        `json:"signature_correctness_proof"`
}

type Credential struct {
	SchemaId                  SchemaID
	CredDefId                 CredDefID
	Values                    map[string]interface{}
	Signature                 []byte
	SignatureCorrectnessProof []byte
}

func (d *Credential) ForCL() (*cl.Credential, error) {
	return &cl.Credential{
		Signature: d.Signature,
		Values:    d.Values,
		SigProof:  d.SignatureCorrectnessProof,
	}, nil
}

func (d *Credential) Process(prover cl.Prover, resolver Resolver) error {
	clCred, err := d.ForCL()
	if err != nil {
		return err
	}

	// TODO: check how and where to get cred request on the prover side
	var clReq *cl.CredentialRequest

	credDef, err := resolver.ResolveCredDef(d.CredDefId)
	if err != nil {
		return err
	}

	err = prover.ProcessCredential(clCred, clReq, credDef)
	return err
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
		SchemaId:                  SchemaID(raw.SchemaId),
		CredDefId:                 CredDefID(raw.CredDefId),
		Values:                    raw.Values,
		Signature:                 raw.Signature,
		SignatureCorrectnessProof: raw.SignatureCorrectnessProof,
	}, nil
}

func validateCredential(data *Credential) error {
	return nil
}
