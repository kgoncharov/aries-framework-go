/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

const (
	// CredFilterFormatV2 format identifier.
	CredFilterFormatV2 = "hlindy/cred-filter@v2.0"
	// CredOfferFormatV2 format identifier.
	CredOfferFormatV2 = "hlindy/cred-abstract@v2.0"
	// CredReqFormatV2 format identifier.
	CredReqFormatV2 = "hlindy/cred-req@v2.0"
	// CredFormatV2 format identifier.
	CredFormatV2 = "hlindy/cred@v2.0"
)

// CredDefID describes Credential Definition ID.
type CredDefID string

// DID describes Decentralized Identifier format.
type DID string

// SchemaID describes Schema ID.
type SchemaID string

// CredValueEntry describes format for value in proposal, offer according rfc0592.
type CredValueEntry struct {
	Raw     interface{} `json:"raw"`
	Encoded int         `json:"encoded"`
}

// CredValues is a map of cred values.
type CredValues = map[string]CredValueEntry

// RawCredValues creates map with raw values of CredVals.
func RawCredValues(vals CredValues) map[string]interface{} {
	raws := make(map[string]interface{})
	for key, val := range vals {
		raws[key] = val.Raw
	}

	return raws
}
