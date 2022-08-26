/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

const (
	CredFilterFormatV2 = "hlindy/cred-filter@v2.0"
	CredOfferFormatV2  = "hlindy/cred-abstract@v2.0"
	CredReqFormatV2    = "hlindy/cred-req@v2.0"
	CredFormatV2       = "hlindy/cred@v2.0"
)

type CredDefID string

type DID string

type SchemaID string

type CredValueEntry struct {
	Raw     interface{} `json:"raw"`
	Encoded int         `json:"encoded"`
}

type CredValues = map[string]CredValueEntry
