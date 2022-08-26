/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package indy

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/cl"
)

type Resolver interface {
	ResolveCredDef(credDefId CredDefID) (*cl.CredentialDefinition, error)
}
