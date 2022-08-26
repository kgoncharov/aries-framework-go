//go:build ursa
// +build ursa

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIndyAttachments(t *testing.T) {

	const (
		schemaIssuerDid = "did:sov:4RW6QK2HZhHxa2tg7t1jqt"
		schemaName      = "bcgov-mines-act-permit.bcgov-mines-permitting"
		schemaId        = "4RW6QK2HZhHxa2tg7t1jqt:2:bcgov-mines-act-permit.bcgov-mines-permitting:0.2.0"
		credDefId       = "4RW6QK2HZhHxa2tg7t1jqt:3:CL:58160:default"

		issuerDid = "did:sov:4RW6QK2HZhHxa2tg7t1jqt"
		proverDid = "did:sov:abcxyz123"
	)

	credProposal := fmt.Sprintf(`{
		"schema_issuer_did": "%s",
		"schema_name": "%s",
		"issuer_did": "%s"
	}`, schemaIssuerDid,
		schemaName,
		issuerDid,
	)

	offerNonce := "57a62300-fbe2-4f08-ace0-6c329c5210e1"

	credOffer := fmt.Sprintf(`{
		"schema_id": "%s",
		"cred_def_id": "%s",
		"nonce": "%s",
		"key_correctness_proof" : {"type":"offer_proof"}
	}`, schemaId,
		credDefId,
		offerNonce,
	)

	requestNonce := "fbe22300-57a6-4f08-ace0-9c5210e16c32"

	credRequest := fmt.Sprintf(`{
		"prover_did" : "%s",
		"cred_def_id" : "%s",
		"blinded_ms" : {"type":"ms"},
		"blinded_ms_correctness_proof" : {"type":"ms_proof"},
		"nonce": "%s"
	}`, proverDid,
		credDefId,
		requestNonce,
	)

	// TODO: update test after refactoring to correct Values format
	cred := fmt.Sprintf(`{
		"schema_id": "%s",
		"cred_def_id": "%s",
		"values": {
			"attr1" : 1,
			"attr2" : "test"
		},
		"signature": {"type":"signature"},
		"signature_correctness_proof": {"type":"signature_proof"}
	}`, schemaId,
		credDefId,
	)

	t.Run("test CredentialProposal parsing", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(credProposal))

		proposal, err := ParseCredentialProposal(encoded)

		require.NoError(t, err)
		require.Equal(t, schemaName, proposal.SchemaName)
		require.Equal(t, DID(issuerDid), proposal.IssuerDid)
		require.Equal(t, DID(schemaIssuerDid), proposal.SchemaIssuerDid)
	})

	t.Run("test CredentialOffer parsing", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(credOffer))

		offer, err := ParseCredentialOffer(encoded)

		require.NoError(t, err)
		require.Equal(t, CredDefID(credDefId), offer.CredDefId)
		require.Equal(t, SchemaID(schemaId), offer.SchemaId)
		require.Equal(t, offerNonce, offer.Nonce)
		require.Equal(t, []byte(`{"type":"offer_proof"}`), offer.KeyCorrectnessProof)
	})

	t.Run("test CredentialRequest parsing", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(credRequest))

		request, err := ParseCredentialRequest(encoded)

		require.NoError(t, err)
		require.Equal(t, DID(proverDid), request.ProverDid)
		require.Equal(t, CredDefID(credDefId), request.CredDefId)
		require.Equal(t, requestNonce, request.Nonce)
		require.Equal(t, []byte(`{"type":"ms"}`), request.BlindedMs)
		require.Equal(t, []byte(`{"type":"ms_proof"}`), request.BlindedMsCorrectnessProof)
	})

	t.Run("test Credential parsing", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(cred))

		credential, err := ParseCredential(encoded)

		require.NoError(t, err)
		require.Equal(t, SchemaID(schemaId), credential.SchemaId)
		require.Equal(t, CredDefID(credDefId), credential.CredDefId)
		require.Equal(t, []byte(`{"type":"signature"}`), credential.Signature)
		require.Equal(t, []byte(`{"type":"signature_proof"}`), credential.SignatureCorrectnessProof)

		require.NotEmpty(t, credential.Values)
		// require.Equal(t, 1, credential.Values["attr1"])
		require.Equal(t, "test", credential.Values["attr2"])
	})

}
