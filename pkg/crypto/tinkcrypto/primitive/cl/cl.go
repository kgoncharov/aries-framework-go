package cl

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

// TODO - find a better way to setup tink than init.
// nolint: gochecknoinits
func init() {
	// TODO - avoid the tink registry singleton.
	err := registry.RegisterKeyManager(newCLSignerKeyManager())
	if err != nil {
		panic(fmt.Sprintf("cl.init() failed: %v", err))
	}
}
