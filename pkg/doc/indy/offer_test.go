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

func TestOffer(t *testing.T) {
	validJSON := `{
		"schema_id": "4RW6QK2HZhHxa2tg7t1jqt:2:permitting:0.2.0",
		"cred_def_id": "4RW6QK2HZhHxa2tg7t1jqt:3:CL:58160:default",
		"nonce": "57a62300-fbe2-4f08-ace0-6c329c5210e1",
		"key_correctness_proof" : {"type":"offer_proof"}
	}`

	t.Run("parse: valid JSON", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(validJSON))

		decoded, err := ParseCredentialOffer(encoded)

		require.NoError(t, err)
		require.Equal(t, SchemaID("4RW6QK2HZhHxa2tg7t1jqt:2:permitting:0.2.0"), decoded.SchemaID)
		require.Equal(t, CredDefID("4RW6QK2HZhHxa2tg7t1jqt:3:CL:58160:default"), decoded.CredDefID)
		require.Equal(t, "57a62300-fbe2-4f08-ace0-6c329c5210e1", decoded.Nonce)
		require.Equal(t, []byte(`{"type":"offer_proof"}`), decoded.KeyCorrectnessProof)
	})

	t.Run("parse: broken base64", func(t *testing.T) {
		_, err := ParseCredentialOffer("not a base 64")

		require.Error(t, err)
	})

	t.Run("parse: broken JSON", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(`{"json":"broken}`))

		_, err := ParseCredentialOffer(encoded)

		require.Error(t, err)
	})
}
