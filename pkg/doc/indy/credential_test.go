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

func TestCredential(t *testing.T) {
	validJSON := `{
		"schema_id": "4RW6QK2HZhHxa2tg7t1jqt:2:permitting:0.2.0",
		"cred_def_id": "4RW6QK2HZhHxa2tg7t1jqt:3:CL:58160:default",
		"values": {
			"attr1" : {"raw": "value1", "encoded": 1111 },
			"attr2" : {"raw": "value2", "encoded": 2222 }
		},
		"signature": {"type":"signature"},
		"signature_correctness_proof": {"type":"signature_proof"}
	}`

	t.Run("parse: valid JSON", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(validJSON))

		decoded, err := ParseCredential(encoded)

		require.NoError(t, err)
		require.Equal(t, SchemaID("4RW6QK2HZhHxa2tg7t1jqt:2:permitting:0.2.0"), decoded.SchemaID)
		require.Equal(t, CredDefID("4RW6QK2HZhHxa2tg7t1jqt:3:CL:58160:default"), decoded.CredDefID)
		require.Equal(t, []byte(`{"type":"signature"}`), decoded.Signature)
		require.Equal(t, []byte(`{"type":"signature_proof"}`), decoded.SignatureCorrectnessProof)

		require.NotEmpty(t, decoded.Values)
		require.Equal(t, CredValueEntry{Raw: "value1", Encoded: 1111}, decoded.Values["attr1"])
		require.Equal(t, CredValueEntry{Raw: "value2", Encoded: 2222}, decoded.Values["attr2"])
	})

	t.Run("parse: broken base64", func(t *testing.T) {
		_, err := ParseCredential("not a base 64")

		require.Error(t, err)
	})

	t.Run("parse: broken JSON", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(`{"json":"broken}`))

		_, err := ParseCredential(encoded)

		require.Error(t, err)
	})
}
