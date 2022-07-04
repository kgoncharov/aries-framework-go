package cl

import (
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	clutil "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/util"
)

func TestCLCredDefKeyTemplateSuccess(t *testing.T) {
	attrs := []string{"attr1", "attr2"}
	values := map[string]interface{}{"attr1": 5, "attr2": "aaa"}

	kt := CredDefKeyTemplate(attrs)

	kh, err := keyset.NewHandle(kt)
	require.NoError(t, err)
	require.NotNil(t, kh)

	pkHandle, err := kh.Public()
	require.NoError(t, err)
	require.NotNil(t, pkHandle)

	// kt := pkHandle.kt
	// s := kt.

	// now test the CL primitives with these keyset handles
	signer, err := NewSigner(kh)
	require.NoError(t, err)

	credDef, err := signer.GetPublicKey()
	require.NoError(t, err)
	require.NotNil(t, credDef)

	//credDef := clutil.CreateCredentialDefinition(t, attrs)
	blindedSecrets, nonce := clutil.CreateBlindedSecrets(t, credDef)
	sig, sigProof, nonce, err := signer.Sign(values, blindedSecrets, nonce)
	require.NoError(t, err)
	require.NotNil(t, sig)
	require.NotNil(t, sigProof)
	require.NotNil(t, nonce)
}
