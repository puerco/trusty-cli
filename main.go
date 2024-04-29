package main

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/stacklok/trusty-attest/internal/packages"
	"github.com/stacklok/trusty-attest/pkg/sbom"
)

func main() {
	l := packages.NewLister()
	ctx := context.Background()
	if len(os.Args) == 1 {
		logrus.Fatal("no directory specified")
	}

	nodelist, err := l.ReadPackages(ctx, os.Args[1])
	if err != nil {
		logrus.Fatal(err)
	}

	scorer := sbom.NewScorer()
	results, err := scorer.ScoreNodeList(ctx, nodelist)
	if err != nil {
		logrus.Fatal(err)
	}

	fmt.Printf("%+v", results)
}
