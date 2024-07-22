package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/spf13/cobra"
	"github.com/stacklok/trusty-attest/pkg/display"
	"github.com/stacklok/trusty-attest/pkg/sbom"
)

type sbomOptions struct {
	SbomPath   string
	File       string
	Transients bool
	Format     string
}

var formats = []string{"term", "csv"}

// Validate checks the options in context with arguments
func (ao *sbomOptions) Validate() error {
	errs := []error{}
	if !slices.Contains(formats, ao.Format) && ao.Format != "" {
		errs = append(errs, fmt.Errorf("invalid format, must be one of %v", formats))
	}
	return nil
}

func (o *sbomOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVarP(
		&o.Transients,
		"transients",
		"t",
		true,
		"include transient dependencies in report",
	)

	cmd.PersistentFlags().StringVarP(
		&o.Format,
		"format",
		"f",
		"term",
		fmt.Sprintf("Output format, one of %v", formats),
	)
}

func addSBOM(parentCmd *cobra.Command) {
	opts := sbomOptions{}
	createCmd := &cobra.Command{
		Short:             "report dependency quality from an SBOM",
		Use:               "sbom [flags] sbom.[spdx|cdx].json",
		Example:           fmt.Sprintf("%s sbom my-sbom.spdx.json", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.SbomPath = args[0]
			}

			if err := opts.Validate(); err != nil {
				return err
			}

			s, err := os.Open(opts.SbomPath)
			if err != nil {
				return fmt.Errorf("opening SBOM: %w", err)
			}

			scorer := sbom.NewScorer()
			results, err := scorer.ScoreSBOM(context.Background(), s)
			if err != nil {
				return fmt.Errorf("scoring nodelist: %w", err)
			}

			var f io.Writer
			if opts.File != "" {
				f, err = os.Create(opts.File)
				if err != nil {
					return fmt.Errorf("opening file: %w", err)
				}
				defer f.(*os.File).Close()
			} else {
				f = os.Stdout
			}

			// Choose the selected renderer
			var renderer display.Renderer
			switch opts.Format {
			case "term":
				renderer = &display.TermRenderer{}
			case "csv":
				renderer = &display.CsvRenderer{}
			}

			renderer.DisplayResultSet(f, results)

			return nil
		},
	}
	opts.AddFlags(createCmd)
	parentCmd.AddCommand(createCmd)
}
