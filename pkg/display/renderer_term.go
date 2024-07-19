package display

import (
	"fmt"
	"io"
	"strconv"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/stacklok/trusty-attest/pkg/trusty"
)

type TermRenderer struct{}

func (tr *TermRenderer) DisplayResultSet(w io.Writer, res []trusty.PackageScore) error {
	var rows = [][]string{}
	for _, s := range res {
		rows = append(rows, []string{
			s.Identifiers["purl"],
			//s.Package, s.Version,
			fmt.Sprintf("%f", s.Score),
		})
	}

	riskyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).
		Bold(true).PaddingLeft(1).PaddingRight(1)

	headerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FAFAFA")).
		Bold(true).Background(lipgloss.Color("#7D56F4"))

	var styleA = lipgloss.NewStyle().
		PaddingLeft(1).
		PaddingRight(1)

	var styleB = lipgloss.NewStyle().
		PaddingLeft(1).
		PaddingRight(1)

	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("99"))).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row > 0 {
				// row -1 because the row number is off by 1 from the data
				// because of the inserted header
				f, err := strconv.ParseFloat(rows[row-1][1], 64)
				if err == nil && f <= 5 {
					return riskyStyle
				}
			}

			switch {
			case row == 0:
				return headerStyle
			case row%2 == 0:
				return styleA
			default:
				return styleB
			}
		}).
		Headers("PACKAGE", "SCORE").
		Rows(rows...)

	if _, err := fmt.Fprint(w, t); err != nil {
		return fmt.Errorf("rendering results set: %w", err)
	}
	fmt.Fprintln(w, "")
	return nil
}
