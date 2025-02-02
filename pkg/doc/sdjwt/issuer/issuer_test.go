/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuer

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/json"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	afjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
)

const (
	issuer                 = "https://example.com/issuer"
	expectedHashWithSpaces = "qqvcqnczAMgYx7EykI6wwtspyvyvK790ge7MBbQ-Nus"
	sampleSalt             = "3jqcb67z9wks08zwiK7EyQ"
)

func TestNew(t *testing.T) {
	claims := createClaims()

	t.Run("Create JWS signed by EdDSA", func(t *testing.T) {
		r := require.New(t)

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		token, err := New(issuer, claims, nil, afjwt.NewEd25519Signer(privKey),
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return sampleSalt, nil
			}))
		r.NoError(err)
		sdJWTSerialized, err := token.Serialize(false)
		require.NoError(t, err)

		fmt.Printf(sdJWTSerialized)

		sdJWT := common.ParseSDJWT(sdJWTSerialized)
		require.Equal(t, 1, len(sdJWT.Disclosures))

		var parsedClaims map[string]interface{}
		err = verifyEd25519ViaGoJose(sdJWT.JWTSerialized, pubKey, &parsedClaims)
		r.NoError(err)

		parsedClaimsBytes, err := json.Marshal(parsedClaims)
		require.NoError(t, err)

		prettyJSON, err := prettyPrint(parsedClaimsBytes)
		require.NoError(t, err)

		fmt.Println(prettyJSON)

		require.True(t, existsInDisclosures(parsedClaims, expectedHashWithSpaces))

		err = verifyEd25519(sdJWT.JWTSerialized, pubKey)
		r.NoError(err)
	})

	t.Run("Create JWS signed by RS256", func(t *testing.T) {
		r := require.New(t)

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)

		pubKey := &privKey.PublicKey

		token, err := New(issuer, claims, nil, afjwt.NewRS256Signer(privKey, nil),
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return sampleSalt, nil
			}))
		r.NoError(err)
		sdJWTSerialized, err := token.Serialize(false)
		require.NoError(t, err)

		sdJWT := common.ParseSDJWT(sdJWTSerialized)
		require.Equal(t, 1, len(sdJWT.Disclosures))

		var parsedClaims map[string]interface{}
		err = verifyRS256ViaGoJose(sdJWT.JWTSerialized, pubKey, &parsedClaims)
		r.NoError(err)

		parsedClaimsBytes, err := json.Marshal(parsedClaims)
		require.NoError(t, err)

		prettyJSON, err := prettyPrint(parsedClaimsBytes)
		require.NoError(t, err)

		fmt.Println(prettyJSON)

		expectedHashWithSpaces := expectedHashWithSpaces
		require.True(t, existsInDisclosures(parsedClaims, expectedHashWithSpaces))

		err = verifyRS256(sdJWT.JWTSerialized, pubKey)
		r.NoError(err)
	})

	t.Run("Create Complex Claims JWS signed by EdDSA", func(t *testing.T) {
		r := require.New(t)

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		r.NoError(err)

		complexClaims := createComplexClaims()

		issued := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
		expiry := time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC)
		notBefore := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

		var newOpts []NewOpt

		newOpts = append(newOpts,
			WithIssuedAt(jwt.NewNumericDate(issued)),
			WithExpiry(jwt.NewNumericDate(expiry)),
			WithNotBefore(jwt.NewNumericDate(notBefore)),
			WithID("id"),
			WithSubject("subject"),
			// TODO: Audience ???
			WithSaltFnc(generateSalt),
			WithJSONMarshaller(json.Marshal),
			WithHashAlgorithm(crypto.SHA256),
		)

		token, err := New(issuer, complexClaims, nil, afjwt.NewEd25519Signer(privKey), newOpts...)
		r.NoError(err)
		sdJWTSerialized, err := token.Serialize(false)
		require.NoError(t, err)

		fmt.Printf(sdJWTSerialized)

		sdJWT := common.ParseSDJWT(sdJWTSerialized)
		require.Equal(t, 7, len(sdJWT.Disclosures))

		var parsedClaims map[string]interface{}
		err = verifyEd25519ViaGoJose(sdJWT.JWTSerialized, pubKey, &parsedClaims)
		r.NoError(err)

		parsedClaimsBytes, err := json.Marshal(parsedClaims)
		require.NoError(t, err)

		prettyJSON, err := prettyPrint(parsedClaimsBytes)
		require.NoError(t, err)

		fmt.Println(prettyJSON)

		err = verifyEd25519(sdJWT.JWTSerialized, pubKey)
		r.NoError(err)
	})

	t.Run("error - wrong hash function", func(t *testing.T) {
		r := require.New(t)

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)
		token, err := New(issuer, claims, nil, afjwt.NewRS256Signer(privKey, nil),
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return sampleSalt, nil
			}),
			WithHashAlgorithm(0))
		r.Error(err)
		r.Nil(token)
		r.Contains(err.Error(), "hash disclosure: hash function not available for: 0")
	})

	t.Run("error - get salt error", func(t *testing.T) {
		r := require.New(t)

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)
		token, err := New(issuer, claims, nil, afjwt.NewRS256Signer(privKey, nil),
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return "", fmt.Errorf("salt error")
			}))
		r.Error(err)
		r.Nil(token)
		r.Contains(err.Error(), "create disclosure: generate salt: salt error")
	})

	t.Run("error - marshal error", func(t *testing.T) {
		r := require.New(t)

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		r.NoError(err)
		token, err := New(issuer, claims, nil, afjwt.NewRS256Signer(privKey, nil),
			WithJSONMarshaller(func(v interface{}) ([]byte, error) {
				return nil, fmt.Errorf("marshal error")
			}))
		r.Error(err)
		r.Nil(token)
		r.Contains(err.Error(), "create disclosure: marshal disclosure: marshal error")
	})
}

func TestJSONWebToken_DecodeClaims(t *testing.T) {
	token, err := getValidJSONWebToken(
		WithJSONMarshaller(jsonMarshalWithSpace),
		WithSaltFnc(func() (string, error) {
			return sampleSalt, nil
		}))
	require.NoError(t, err)

	var tokensMap map[string]interface{}

	err = token.DecodeClaims(&tokensMap)
	require.NoError(t, err)

	expectedHashWithSpaces := expectedHashWithSpaces
	require.True(t, existsInDisclosures(tokensMap, expectedHashWithSpaces))

	var claims Claims

	err = token.DecodeClaims(&claims)
	require.NoError(t, err)
	require.Equal(t, claims.Issuer, issuer)

	token, err = getJSONWebTokenWithInvalidPayload()
	require.NoError(t, err)

	err = token.DecodeClaims(&claims)
	require.Error(t, err)
}

func TestJSONWebToken_LookupStringHeader(t *testing.T) {
	token, err := getValidJSONWebToken()
	require.NoError(t, err)

	require.Equal(t, "JWT", token.LookupStringHeader("typ"))

	require.Empty(t, token.LookupStringHeader("undef"))

	token.SignedJWT.Headers["not_str"] = 55
	require.Empty(t, token.LookupStringHeader("not_str"))
}

func TestJSONWebToken_Serialize(t *testing.T) {
	token, err := getValidJSONWebToken()
	require.NoError(t, err)

	tokenSerialized, err := token.Serialize(false)
	require.NoError(t, err)
	require.NotEmpty(t, tokenSerialized)

	// cannot serialize without signature
	token.SignedJWT = nil
	tokenSerialized, err = token.Serialize(false)
	require.Error(t, err)
	require.EqualError(t, err, "JWS serialization is supported only")
	require.Empty(t, tokenSerialized)
}

func TestJSONWebToken_hashDisclosure(t *testing.T) {
	t.Run("success - data from spec", func(t *testing.T) {
		dh, err := common.GetHash(defaultHash, "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0")
		require.NoError(t, err)
		require.Equal(t, "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY", dh)
	})
}

func TestJSONWebToken_createDisclosure(t *testing.T) {
	t.Run("success - given name", func(t *testing.T) {
		nOpts := getOpts(
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return sampleSalt, nil
			}))

		// Disclosure data from spec: ["3jqcb67z9wks08zwiK7EyQ", "given_name", "John"]
		expectedDisclosureWithSpaces := "WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
		expectedHashWithSpaces := expectedHashWithSpaces

		disclosure, err := createDisclosure("given_name", "John", nOpts)
		require.NoError(t, err)
		require.Equal(t, expectedDisclosureWithSpaces, disclosure)

		dh, err := common.GetHash(defaultHash, disclosure)
		require.NoError(t, err)
		require.Equal(t, expectedHashWithSpaces, dh)
	})

	t.Run("success - family name", func(t *testing.T) {
		// Disclosure data from spec: ["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"]

		expectedDisclosureWithoutSpaces := "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd"
		expectedDisclosureWithSpaces := "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"

		nOpts := getOpts(
			WithSaltFnc(func() (string, error) {
				return "_26bc4LT-ac6q2KI6cBW5es", nil
			}))

		disclosure, err := createDisclosure("family_name", "Möbius", nOpts)
		require.NoError(t, err)
		require.Equal(t, expectedDisclosureWithoutSpaces, disclosure)

		nOpts = getOpts(
			WithJSONMarshaller(jsonMarshalWithSpace),
			WithSaltFnc(func() (string, error) {
				return "_26bc4LT-ac6q2KI6cBW5es", nil
			}))

		disclosure, err = createDisclosure("family_name", "Möbius", nOpts)
		require.NoError(t, err)
		require.Equal(t, expectedDisclosureWithSpaces, disclosure)
	})
}

func getOpts(opts ...NewOpt) *newOpts {
	nOpts := &newOpts{
		jsonMarshal: json.Marshal,
		getSalt:     generateSalt,
		HashAlg:     defaultHash,
	}

	for _, opt := range opts {
		opt(nOpts)
	}

	return nOpts
}

func getValidJSONWebToken(opts ...NewOpt) (*SelectiveDisclosureJWT, error) {
	headers := map[string]interface{}{"typ": "JWT", "alg": "EdDSA"}
	claims := map[string]interface{}{"given_name": "John"}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	signer := afjwt.NewEd25519Signer(privKey)

	return New(issuer, claims, headers, signer, opts...)
}

func getJSONWebTokenWithInvalidPayload() (*SelectiveDisclosureJWT, error) {
	token, err := getValidJSONWebToken()
	if err != nil {
		return nil, err
	}

	// hack the token
	token.SignedJWT.Payload = getUnmarshallableMap()

	return token, nil
}

func verifyEd25519ViaGoJose(jws string, pubKey ed25519.PublicKey, claims interface{}) error {
	jwtToken, err := jwt.ParseSigned(jws)
	if err != nil {
		return fmt.Errorf("parse VC from signed JWS: %w", err)
	}

	if err = jwtToken.Claims(pubKey, claims); err != nil {
		return fmt.Errorf("verify JWT signature: %w", err)
	}

	return nil
}

func verifyRS256ViaGoJose(jws string, pubKey *rsa.PublicKey, claims interface{}) error {
	jwtToken, err := jwt.ParseSigned(jws)
	if err != nil {
		return fmt.Errorf("parse VC from signed JWS: %w", err)
	}

	if err = jwtToken.Claims(pubKey, claims); err != nil {
		return fmt.Errorf("verify JWT signature: %w", err)
	}

	return nil
}

func getUnmarshallableMap() map[string]interface{} {
	return map[string]interface{}{"error": map[chan int]interface{}{make(chan int): 6}}
}

func createClaims() map[string]interface{} {
	claims := map[string]interface{}{
		"given_name": "John",
	}

	return claims
}

func createComplexClaims() map[string]interface{} {
	claims := map[string]interface{}{
		"sub":          "john_doe_42",
		"given_name":   "John",
		"family_name":  "Doe",
		"email":        "johndoe@example.com",
		"phone_number": "+1-202-555-0101",
		"birthdate":    "1940-01-01",
		"address": map[string]interface{}{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"region":         "Anystate",
			"country":        "US",
		},
	}

	return claims
}

func verifyEd25519(jws string, pubKey ed25519.PublicKey) error {
	v, err := afjwt.NewEd25519Verifier(pubKey)
	if err != nil {
		return err
	}

	sVerifier := jose.NewCompositeAlgSigVerifier(jose.AlgSignatureVerifier{
		Alg:      "EdDSA",
		Verifier: v,
	})

	token, err := afjwt.Parse(jws, afjwt.WithSignatureVerifier(sVerifier))
	if err != nil {
		return err
	}

	if token == nil {
		return errors.New("nil token")
	}

	return nil
}

func verifyRS256(jws string, pubKey *rsa.PublicKey) error {
	v := afjwt.NewRS256Verifier(pubKey)

	sVerifier := jose.NewCompositeAlgSigVerifier(jose.AlgSignatureVerifier{
		Alg:      "RS256",
		Verifier: v,
	})

	token, err := afjwt.Parse(jws, afjwt.WithSignatureVerifier(sVerifier))
	if err != nil {
		return err
	}

	if token == nil {
		return errors.New("nil token")
	}

	return nil
}

func existsInDisclosures(claims map[string]interface{}, val string) bool {
	disclosuresObj, ok := claims[common.SDKey]
	if !ok {
		return false
	}

	disclosures, ok := disclosuresObj.([]interface{})
	if !ok {
		return false
	}

	for _, d := range disclosures {
		if d.(string) == val {
			return true
		}
	}

	return false
}

func jsonMarshalWithSpace(v interface{}) ([]byte, error) {
	vBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	return []byte(strings.ReplaceAll(string(vBytes), ",", ", ")), nil
}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}
