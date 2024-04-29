package sbom

import (
	"context"
	"fmt"

	"github.com/bom-squad/protobom/pkg/sbom"
	v1 "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
	"github.com/stacklok/trusty-attest/pkg/trusty"
)

func NewScorer() *Scorer {
	return &Scorer{
		trusty: *trusty.NewClient(),
	}
}

type Scorer struct {
	trusty trusty.Client
}

func (s *Scorer) ScoreNodeList(ctx context.Context, nl *sbom.NodeList) ([]trusty.PackageScore, error) {
	// Index the top level IDs
	tlID := map[string]struct{}{}
	for _, i := range nl.RootElements {
		tlID[i] = struct{}{}
	}
	scores := []trusty.PackageScore{}
	for _, n := range nl.Nodes {
		if _, ok := tlID[n.Id]; ok {
			continue
		}
		score, err := s.ScoreNode(ctx, n)
		if err != nil {
			return nil, fmt.Errorf("fetching data from trusty: %w", err)
		}
		scores = append(scores, score)
	}
	return scores, nil
}

// ScoreNode returns the trusty scrore for a protobom node
func (s *Scorer) ScoreNode(ctx context.Context, n *sbom.Node) (trusty.PackageScore, error) {
	// TODO(puerco): Resolve ecosystem
	res, err := s.trusty.DoRequest(ctx, &v1.Dependency{
		Ecosystem: v1.DepEcosystem_DEP_ECOSYSTEM_GO,
		Name:      n.Name,
		Version:   n.Version,
	})
	if err != nil {
		return trusty.PackageScore{}, fmt.Errorf("calling trusty api: %w", err)
	}

	ids := map[string]string{}

	if _, ok := n.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]; ok {
		ids["purl"] = n.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]
	}

	if _, ok := n.Identifiers[int32(sbom.SoftwareIdentifierType_CPE23)]; ok {
		ids["cpe23"] = n.Identifiers[int32(sbom.SoftwareIdentifierType_CPE23)]
	}

	if _, ok := n.Identifiers[int32(sbom.SoftwareIdentifierType_CPE22)]; ok {
		ids["cpe22"] = n.Identifiers[int32(sbom.SoftwareIdentifierType_CPE22)]
	}

	return trusty.PackageScore{
		PackageInfo: trusty.PackageInfo{
			Package:     n.Name,
			Version:     n.Version,
			Identifiers: ids,
		},
		Score:   res.Summary.Score,
		Details: res.Summary.Description,
	}, nil
}
