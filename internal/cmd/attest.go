package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
	"github.com/stacklok/trusty-attest/internal/packages"
	"github.com/stacklok/trusty-attest/pkg/sbom"
	"github.com/stacklok/trusty-attest/pkg/trusty"
)

type attestOptions struct {
	Bundle bool
}

// Validates the options in context with arguments
func (ao *attestOptions) Validate() error {
	return nil
}

func (o *attestOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVarP(
		&o.Bundle,
		"bundle",
		"b",
		false,
		"create a signed sigstore bundle (runs the oauth flow)",
	)

}

func addAttest(parentCmd *cobra.Command) {
	opts := attestOptions{}
	createCmd := &cobra.Command{
		Short:             fmt.Sprintf("%s attest: generates a trusty attestation", appname),
		Use:               "attest [flags] [product_id [vuln_id [status]]]",
		Example:           fmt.Sprintf("%s attest repository/path/ ", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(_ *cobra.Command, args []string) error {
			l := packages.NewLister()
			ctx := context.Background()
			if len(args) == 0 {
				return fmt.Errorf("no directory specified")
			}

			nodelist, err := l.ReadPackages(ctx, args[0])
			if err != nil {
				return fmt.Errorf("reading packages: %w", err)
			}

			scorer := sbom.NewScorer()
			results, err := scorer.ScoreNodeList(ctx, nodelist)
			if err != nil {
				return fmt.Errorf("scoring nodelist: %w", err)
			}

			pred, err := trusty.BuildPredicate(trusty.PredicateOpts{}, results)
			if err != nil {
				return fmt.Errorf("building attestation predicate: %w", err)
			}

			att, err := trusty.Attest([]intoto.Subject{}, pred)

			f := os.Stdout
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)

			if err := enc.Encode(att); err != nil {
				return fmt.Errorf("encoding attestation: %w", err)
			}

			return nil
		},
	}
	opts.AddFlags(createCmd)
	parentCmd.AddCommand(createCmd)
}
