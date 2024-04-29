package trusty

import (
	"context"
	"fmt"

	"github.com/bom-squad/protobom/pkg/sbom"
	v1 "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
)

type Client struct {
	client *trustyClient
}

func NewClient() *Client {
	return &Client{
		client: NewPiClient("https://api.trustypkg.dev"),
	}
}

// RankNode returns the trusty scrore for a protobom node
func (c *Client) NodeScore(n *sbom.Node) (ScoreSummary, error) {
	// Do the call
	res, err := c.client.SendRecvRequest(context.Background(), &v1.Dependency{
		// Ecosystem: v1.DepEcosystem_DEP_ECOSYSTEM_PYPI,
		Ecosystem: v1.DepEcosystem_DEP_ECOSYSTEM_GO,
		Name:      n.Name,
		Version:   n.Version,
	})
	if err != nil {
		return ScoreSummary{}, fmt.Errorf("calling trusty api: %w", err)
	}

	return res.Summary, nil
}
