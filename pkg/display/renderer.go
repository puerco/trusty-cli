package display

import (
	"io"

	"github.com/stacklok/trusty-attest/pkg/trusty"
)

type Renderer interface {
	DisplayResultSet(io.Writer, []trusty.PackageScore) error
}
