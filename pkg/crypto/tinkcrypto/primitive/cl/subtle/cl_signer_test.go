package subtle

import (
	"testing"

	clapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/api"
	clutil "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/util"
	"github.com/stretchr/testify/require"
)

func TestIsCLSigner(t *testing.T) {
	attrs := []string{"attr1", "attr2"}
	credDef := clutil.CreateCredentialDefinition(t, attrs)
	clSigner, err := NewCLSigner(clutil.GetKeys(t, credDef))
	require.NoError(t, err)

	_, ok := interface{}(clSigner).(clapi.Signer)
	require.True(t, ok)
}

func TestCLSign(t *testing.T) {
	attrs := []string{"attr1", "attr2"}
	values := map[string]interface{}{"attr1": 5, "attr2": "aaa"}

	credDef := clutil.CreateCredentialDefinition(t, attrs)
	clSigner, err := NewCLSigner(clutil.GetKeys(t, credDef))
	require.NoError(t, err)

	blindedSecrets, nonce := clutil.CreateBlindedSecrets(t, credDef)
	sig, sigProof, nonce, err := clSigner.Sign(values, blindedSecrets, nonce)
	require.NoError(t, err)
	require.NotNil(t, sig)
	require.NotNil(t, sigProof)
	require.NotNil(t, nonce)
}

func TestCLGetPubKey(t *testing.T) {
	attrs := []string{"attr1", "attr2"}
	credDef := clutil.CreateCredentialDefinition(t, attrs)
	clSigner, err := NewCLSigner(clutil.GetKeys(t, credDef))
	require.NoError(t, err)

	pk, err := clSigner.GetPublicKey()
	require.NoError(t, err)
	require.NotNil(t, pk)
}
