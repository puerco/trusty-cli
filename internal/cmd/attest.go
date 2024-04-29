package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/puerco/bind/pkg/bundle"
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
		Use:               "attest repository/path/",
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

			// Create the attestation
			att, err := trusty.Attest([]intoto.Subject{}, pred)

			f := os.Stdout
			b := bytes.Buffer{}
			enc := json.NewEncoder(&b)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)

			if err := enc.Encode(att); err != nil {
				return fmt.Errorf("encoding attestation: %w", err)
			}

			if !opts.Bundle {
				if _, err := b.WriteTo(f); err != nil {
					return err
				}
				return nil
			}

			// If bundle, bind the attestation, this kicks off the
			// sigstore flow
			signer := bundle.NewSigner()
			bndl, err := signer.SignAndBind(ctx, b.Bytes())
			if err != nil {
				return fmt.Errorf("signing and binding attestation: %w", err)
			}

			// Clear the buffer
			b.Truncate(0)

			if err := enc.Encode(bndl); err != nil {
				return fmt.Errorf("encoding bundle: %w", err)
			}

			if _, err := b.WriteTo(f); err != nil {
				return err
			}

			return nil
		},
	}
	opts.AddFlags(createCmd)
	parentCmd.AddCommand(createCmd)
}
