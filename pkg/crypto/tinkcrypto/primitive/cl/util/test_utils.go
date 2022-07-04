package util

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

func GetKeys(t *testing.T, credDef *ursa.CredentialDef) ([]byte, []byte, []byte) {
	privKeyJson, err := credDef.PrivKey.ToJSON()
	assert.NoError(t, err)
	pubKeyJson, err := credDef.PubKey.ToJSON()
	assert.NoError(t, err)
	proofJson, err := credDef.KeyCorrectnessProof.ToJSON()
	assert.NoError(t, err)
	return privKeyJson, pubKeyJson, proofJson

}

func CreateCredentialDefinition(t *testing.T, attrs []string) *ursa.CredentialDef {
	schema := CreateSchema(t, []string{"attr1", "attr2"})
	nonSchema := CreateNonSchema(t, []string{"master_secret"})
	credDef, err := ursa.NewCredentialDef(schema, nonSchema, false)
	assert.NoError(t, err)
	return credDef
}

func CreateSchema(t *testing.T, fields []string) *ursa.CredentialSchemaHandle {
	schemaBuilder, err := ursa.NewCredentialSchemaBuilder()
	assert.NoError(t, err)

	for _, field := range fields {
		err = schemaBuilder.AddAttr(field)
		assert.NoError(t, err)
	}

	schema, err := schemaBuilder.Finalize()
	assert.NoError(t, err)

	return schema
}

func CreateNonSchema(t *testing.T, fields []string) *ursa.NonCredentialSchemaHandle {
	nonSchemaBuilder, err := ursa.NewNonCredentialSchemaBuilder()
	assert.NoError(t, err)

	for _, field := range fields {
		err = nonSchemaBuilder.AddAttr(field)
		assert.NoError(t, err)
	}

	nonSchema, err := nonSchemaBuilder.Finalize()
	assert.NoError(t, err)

	return nonSchema
}

func CreateBlindedSecrets(t *testing.T, credDef *ursa.CredentialDef) (*ursa.BlindedCredentialSecrets, *ursa.Nonce) {
	masterSecret, err := ursa.NewMasterSecret()
	assert.NoError(t, err)
	js, err := masterSecret.ToJSON()
	assert.NoError(t, err)
	m := struct {
		MS string `json:"ms"`
	}{}
	err = json.Unmarshal(js, &m)
	assert.NoError(t, err)

	valuesBuilder, err := ursa.NewValueBuilder()
	assert.NoError(t, err)
	err = valuesBuilder.AddDecHidden("master_secret", m.MS)
	assert.NoError(t, err)

	values, err := valuesBuilder.Finalize()
	assert.NoError(t, err)

	credentialNonce, err := ursa.NewNonce()
	assert.NoError(t, err)

	blindedSecrets, err := ursa.BlindCredentialSecrets(credDef.PubKey, credDef.KeyCorrectnessProof, credentialNonce, values)
	assert.NoError(t, err)

	return blindedSecrets, credentialNonce
}

// func getCredDefPublicKey(t *testing.T, kh *keyset.Handle) *ursa.CredentialDef {
// 	pbHandle, err := kh.Public()
// 	assert.NoError(t, err)

// 	pm, err := pbHandle.Primitives()
// 	assert.NoError(t, err)

// 	signer, ok := (pm.Primary.Primitive).(clapi.Signer)
// 	return signer.
// }
