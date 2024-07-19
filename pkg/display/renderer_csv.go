package display

import (
	"encoding/csv"
	"fmt"
	"io"

	"github.com/stacklok/trusty-attest/pkg/trusty"
)

type CsvRenderer struct {
}

func (cr *CsvRenderer) DisplayResultSet(w io.Writer, res []trusty.PackageScore) error {
	records := [][]string{
		{"purl", "name", "version", "score"},
	}
	for _, r := range res {
		records = append(records, []string{
			r.Package, r.Version, r.Identifiers["purl"], fmt.Sprintf("%f", r.Score),
		})
	}

	if err := csv.NewWriter(w).WriteAll(records); err != nil {
		return fmt.Errorf("writing CSV data: %w", err)
	}
	return nil
}
