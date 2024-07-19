package display

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/stacklok/trusty-attest/pkg/trusty"
)

type CsvRenderer struct {
}

var intLabels = map[bool]string{
	true: "1", false: "0",
}

func (cr *CsvRenderer) DisplayResultSet(w io.Writer, res []trusty.PackageScore) error {
	records := [][]string{
		{"ecosystem", "name", "version", "purl", "score", "activity", "provenance", "deprecated", "malicious"},
	}
	for _, r := range res {
		records = append(records, []string{
			strings.ToLower(r.Ecosystem), r.Package, r.Version, r.Identifiers["purl"],
			// TODO(puerco): Add activity
			"0",
			fmt.Sprintf("%f", r.Score), fmt.Sprintf("%f", r.ProvenanceScore),
			intLabels[r.Deprecated], intLabels[r.Malicious],
		})
	}

	if err := csv.NewWriter(w).WriteAll(records); err != nil {
		return fmt.Errorf("writing CSV data: %w", err)
	}
	return nil
}
