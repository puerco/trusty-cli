package sbom

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/sirupsen/logrus"

	"github.com/stacklok/trusty-sdk-go/pkg/client"
	"github.com/stacklok/trusty-sdk-go/pkg/types"

	"github.com/stacklok/trusty-attest/pkg/trusty"
)

type TrustyAPIError struct {
	error
}

func NewScorer() *Scorer {
	return &Scorer{
		trusty: *client.New(),
	}
}

type Scorer struct {
	trusty client.Trusty
}

func (s *Scorer) ScoreSBOM(ctx context.Context, f io.ReadSeeker) ([]trusty.PackageScore, error) {
	r := reader.New()
	doc, err := r.ParseStream(f)
	if err != nil {
		return nil, fmt.Errorf("unable to parse file")
	}

	if len(doc.NodeList.RootElements) == 0 {
		return nil, fmt.Errorf("SBOM has no top evel elements")
	}

	n2 := sbom.NewNodeList()
	for _, n := range doc.NodeList.Nodes {
		p := n.Purl()
		if p == "" {
			continue
		}
		if strings.Contains(string(p), "pkg:golang") ||
			strings.Contains(string(p), "pkg:npm") ||
			strings.Contains(string(p), "pkg:pypi") {
			n2.AddNode(n)
		}
	}

	return s.ScoreNodeList(ctx, n2)
}

func (s *Scorer) ScoreNodeList(ctx context.Context, nl *sbom.NodeList) ([]trusty.PackageScore, error) {
	// Index the top level IDs
	tlID := map[string]struct{}{}
	for _, i := range nl.RootElements {
		tlID[i] = struct{}{}
	}
	scores := []trusty.PackageScore{}
	fmt.Printf("Scoring %d dependencies", len(nl.Nodes))
	defer fmt.Println("")
	for _, n := range nl.Nodes {
		fmt.Print(".")
		if _, ok := tlID[n.Id]; ok {
			continue
		}
		score, err := s.ScoreNode(ctx, n)
		if score == nil {
			continue
		}
		if err != nil {
			// If we get an error calling trusty, skip the package for now
			if _, ok := err.(TrustyAPIError); ok {
				logrus.Errorf("error fetching score for %q", n.Purl())
				continue
			}
			return nil, fmt.Errorf("fetching data from trusty: %w", err)
		}
		scores = append(scores, *score)
	}
	return scores, nil
}

func purlToEcosystem(purl string) types.Ecosystem {
	switch {
	case strings.HasPrefix(purl, "pkg:golang"):
		return types.ECOSYSTEM_GO
	case strings.HasPrefix(purl, "pkg:npm"):
		return types.ECOSYSTEM_NPM
	case strings.HasPrefix(purl, "pkg:pypi"):
		return types.ECOSYSTEM_PYPI
	default:
		return types.Ecosystem(0)
	}
}

// ScoreNode returns the trusty scrore for a protobom node
func (s *Scorer) ScoreNode(ctx context.Context, n *sbom.Node) (*trusty.PackageScore, error) {
	e := purlToEcosystem(string(n.Purl()))
	if e == 0 {
		// Ecosystem nil or not supported
		return nil, nil
	}

	purl, err := packageurl.FromString(string(n.Purl()))
	if err != nil {
		return nil, fmt.Errorf("sbom contains invalid purl %q: %w", n.Purl(), err)
	}
	name := purl.Name
	if purl.Namespace != "" {
		name = purl.Namespace + "/" + purl.Name
	}
	res, err := s.trusty.Report(ctx, &types.Dependency{
		Ecosystem: e,
		Name:      name,
		Version:   purl.Version,
	})
	if err != nil {
		return &trusty.PackageScore{},
			TrustyAPIError{fmt.Errorf("calling trusty api to score %q: %w", n.Purl(), err)}
	}

	logrus.Debugf("Scored %s:%s@%s", purl.Type, name, purl.Version)

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

	return &trusty.PackageScore{
		PackageInfo: trusty.PackageInfo{
			Package:     n.Name,
			Version:     n.Version,
			Identifiers: ids,
		},
		Score:   *res.Summary.Score,
		Details: res.Summary.Description,
	}, nil
}
