package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/puerco/bind/pkg/bundle"
	"github.com/spf13/cobra"
	"github.com/stacklok/trusty-attest/internal/packages"
	"github.com/stacklok/trusty-attest/pkg/sbom"
	"github.com/stacklok/trusty-attest/pkg/trusty"
)

type attestOptions struct {
	Bundle        bool
	PredicateOnly bool
	File          string
}

// Validates the options in context with arguments
func (ao *attestOptions) Validate() error {
	if ao.Bundle && ao.PredicateOnly {
		return fmt.Errorf("cannot define --bundle and --predicate-only at the same time")
	}
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

	cmd.PersistentFlags().BoolVarP(
		&o.PredicateOnly,
		"predicate-only",
		"p",
		false,
		"dont't output a full statement, only the predicate",
	)

	cmd.PersistentFlags().StringVarP(
		&o.File,
		"file",
		"f",
		"",
		"write output to file path (default STDOUT)",
	)
}

func addAttest(parentCmd *cobra.Command) {
	opts := attestOptions{}
	createCmd := &cobra.Command{
		Short:             "generate Trusty attestations from source code",
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

			if err := opts.Validate(); err != nil {
				return err
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

			b := bytes.Buffer{}
			enc := json.NewEncoder(&b)
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)

			if opts.PredicateOnly {
				if err := enc.Encode(pred); err != nil {
					return fmt.Errorf("encoding predicate: %w", err)
				}
				if _, err := b.WriteTo(f); err != nil {
					return fmt.Errorf("writing predicate: %w", err)
				}
				return nil
			}

			// Create the attestation
			att, err := trusty.Attest([]intoto.Subject{}, pred)

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
