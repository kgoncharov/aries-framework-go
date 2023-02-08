/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProposal(t *testing.T) {
	validJSON := `{
		"schema_issuer_did": "did:sov:4RW6QK2HZhHxa2tg7t1jqt",
		"schema_name": "permitting",
		"schema_version": "1.0",
		"issuer_did": "did:sov:abcxyz123",
		"schema_id": "4RW6QK2HZhHxa2tg7t1jqt:2:permitting:0.2.0",
		"cred_def_id": "4RW6QK2HZhHxa2tg7t1jqt:3:CL:58160:default"
	}`

	t.Run("parse: valid JSON", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(validJSON))

		decoded, err := ParseCredentialProposal(encoded)

		require.NoError(t, err)
		require.Equal(t, SchemaID("4RW6QK2HZhHxa2tg7t1jqt:2:permitting:0.2.0"), decoded.SchemaID)
		require.Equal(t, CredDefID("4RW6QK2HZhHxa2tg7t1jqt:3:CL:58160:default"), decoded.CredDefID)
		require.Equal(t, DID("did:sov:4RW6QK2HZhHxa2tg7t1jqt"), decoded.SchemaIssuerDID)
		require.Equal(t, DID("did:sov:abcxyz123"), decoded.IssuerDID)
		require.Equal(t, "permitting", decoded.SchemaName)
		require.Equal(t, "1.0", decoded.SchemaVersion)
	})

	t.Run("parse: broken base64", func(t *testing.T) {
		_, err := ParseCredentialProposal("not a base 64")

		require.Error(t, err)
	})

	t.Run("parse: broken JSON", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(`{"json":"broken}`))

		_, err := ParseCredentialProposal(encoded)

		require.Error(t, err)
	})
}
