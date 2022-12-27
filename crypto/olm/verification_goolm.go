//go:build !nosas && goolm

package olm

import (
	"codeberg.org/DerLukas/goolm/sas"
)

// SAS stores an Olm Short Authentication String (SAS) object.
type SAS struct {
	sas.SAS
}

// NewSAS creates a new SAS object.
func NewSAS() *SAS {
	newSAS, err := sas.New()
	if err != nil {
		panic(err)
	}
	return &SAS{
		SAS: *newSAS,
	}
}
