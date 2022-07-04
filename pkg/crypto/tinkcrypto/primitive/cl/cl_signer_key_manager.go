package cl

import (
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	clsubtle "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/subtle"
	clpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/cl_go_proto"
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

const (
	clSignerKeyVersion = 0
	clSignerKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.CLSignerKey"
)

// common errors.
var (
	errInvalidCLSignerKey       = errors.New("cl_signer_key_manager: invalid key")
	errInvalidCLSignerKeyFormat = errors.New("cl_signer_key_manager: invalid key format")
)

// clSignerKeyManager is an implementation of KeyManager interface for CL signatures/proofs.
// It generates new CredDefPrivateKeys and produces new instances of CLSign subtle.
type clSignerKeyManager struct{}

// newBBSSignerKeyManager creates a new bbsSignerKeyManager.
func newCLSignerKeyManager() *clSignerKeyManager {
	return new(clSignerKeyManager)
}

// Primitive creates a CL Signer subtle for the given serialized CredDefPrivateKey proto.
func (km *clSignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidCLSignerKey
	}

	key := new(clpb.CLCredDefPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKey.Error()+": invalid proto: %w", err)
	}

	err = km.validateKey(key)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKey.Error()+": %w", err)
	}

	clSigner, err := clsubtle.NewCLSigner(key.KeyValue, key.PublicKey.KeyValue, key.PublicKey.KeyCorrectnessProof)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKey.Error()+": %w", err)
	}

	return clSigner, nil
}

// NewKey creates a new key according to the specification of CLCredDefPrivateKey format.
func (km *clSignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidCLSignerKeyFormat
	}

	// 1. Unmarshal to KeyFormat
	keyFormat := new(clpb.CLCredDefKeyFormat)
	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKeyFormat.Error()+": invalid proto: %w", err)
	}
	err = validateKeyFormat(keyFormat)
	if err != nil {
		return nil, fmt.Errorf(errInvalidCLSignerKeyFormat.Error()+": %w", err)
	}

	// 2. Create Credentials Schema
	schemaBuilder, err := ursa.NewCredentialSchemaBuilder()
	if err != nil {
		return nil, err
	}
	for _, field := range keyFormat.Params.Attrs {
		err = schemaBuilder.AddAttr(field)
		if err != nil {
			return nil, err
		}
	}
	schema, err := schemaBuilder.Finalize()
	if err != nil {
		return nil, err
	}

	// 3. Create nonCredentials Schema (for master secret)
	nonSchemaBuilder, err := ursa.NewNonCredentialSchemaBuilder()
	if err != nil {
		return nil, err
	}
	err = nonSchemaBuilder.AddAttr("master_secret")
	if err != nil {
		return nil, err
	}
	nonSchema, err := nonSchemaBuilder.Finalize()
	if err != nil {
		return nil, err
	}

	// 4. Create CredDef
	credDef, err := ursa.NewCredentialDef(schema, nonSchema, false)
	if err != nil {
		return nil, err
	}

	// 5. serialize keys to JSONs
	pubKeyBytes, err := credDef.PubKey.ToJSON()
	if err != nil {
		return nil, err
	}
	privKeyBytes, err := credDef.PrivKey.ToJSON()
	if err != nil {
		return nil, err
	}
	correctnessProofBytes, err := credDef.KeyCorrectnessProof.ToJSON()
	if err != nil {
		return nil, err
	}

	return &clpb.CLCredDefPrivateKey{
		Version:  clSignerKeyVersion,
		KeyValue: privKeyBytes,
		PublicKey: &clpb.CLCredDefPublicKey{
			Version:             clSignerKeyVersion,
			Params:              keyFormat.Params,
			KeyValue:            pubKeyBytes,
			KeyCorrectnessProof: correctnessProofBytes,
		},
	}, nil
}

// NewKeyData creates a new KeyData according to the specification of CLCredDefPrivateKey Format.
// It should be used solely by the key management API.
func (km *clSignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("cl_signer_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         clSignerKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData returns the enclosed public key data of serializedPrivKey.
func (km *clSignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(clpb.CLCredDefPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidCLSignerKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidCLSignerKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         clSignerKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *clSignerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == clSignerKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *clSignerKeyManager) TypeURL() string {
	return clSignerKeyTypeURL
}

// validateKey validates the given CLCredDefPrivateKey
func (km *clSignerKeyManager) validateKey(key *clpb.CLCredDefPrivateKey) error {
	err := keyset.ValidateKeyVersion(key.Version, clSignerKeyVersion)
	if err != nil {
		return fmt.Errorf("cl_signer_key_manager: invalid key: %w", err)
	}
	return nil
}

func validateKeyFormat(format *clpb.CLCredDefKeyFormat) error {
	return nil
}
