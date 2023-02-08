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

func TestRequest(t *testing.T) {
	validJSON := `{
		"prover_did" : "did:sov:abcxyz123",
		"cred_def_id" : "4RW6QK2HZhHxa2tg7t1jqt:3:CL:58160:default",
		"blinded_ms" : {"type":"ms"},
		"blinded_ms_correctness_proof" : {"type":"ms_proof"},
		"nonce": "57a62300-fbe2-4f08-ace0-6c329c5210e1"
	}`

	t.Run("parse: valid JSON", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(validJSON))

		decoded, err := ParseCredentialRequest(encoded)

		require.NoError(t, err)
		require.Equal(t, DID("did:sov:abcxyz123"), decoded.ProverDID)
		require.Equal(t, CredDefID("4RW6QK2HZhHxa2tg7t1jqt:3:CL:58160:default"), decoded.CredDefID)
		require.Equal(t, []byte(`{"type":"ms"}`), decoded.BlindedMs)
		require.Equal(t, []byte(`{"type":"ms_proof"}`), decoded.BlindedMsCorrectnessProof)
		require.Equal(t, "57a62300-fbe2-4f08-ace0-6c329c5210e1", decoded.Nonce)
	})

	t.Run("parse: broken base64", func(t *testing.T) {
		_, err := ParseCredentialRequest("not a base 64")

		require.Error(t, err)
	})

	t.Run("parse: broken JSON", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(`{"json":"broken}`))

		_, err := ParseCredentialRequest(encoded)

		require.Error(t, err)
	})
}
