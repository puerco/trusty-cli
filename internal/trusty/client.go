package trusty

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	pb "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
)

type Client struct {
	client  *http.Client
	baseUrl string
}

func NewClient() *Client {
	return &Client{
		baseUrl: "https://api.trustypkg.dev",
		client:  &http.Client{},
	}
}

func (c *Client) newRequest(ctx context.Context, dep *pb.Dependency) (*http.Request, error) {
	u, err := urlFromEndpointAndPaths(
		c.baseUrl, "v1/report", dep.Name, strings.ToLower(dep.Ecosystem.AsString()),
	)
	if err != nil {
		return nil, fmt.Errorf("could not parse endpoint: %w", err)
	}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}
	req = req.WithContext(ctx)
	return req, nil
}

func (c *Client) DoRequest(ctx context.Context, dep *pb.Dependency) (*Response, error) {
	req, err := c.newRequest(ctx, dep)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 response: %d", resp.StatusCode)
	}

	var response Response
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&response); err != nil {
		return nil, fmt.Errorf("could not unmarshal response: %w", err)
	}

	return &response, nil
}

func urlFromEndpointAndPaths(
	baseUrl string,
	endpoint string,
	packageName string,
	ecosystem string,
) (*url.URL, error) {
	u, err := url.Parse(baseUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse endpoint: %w", err)
	}
	u = u.JoinPath(endpoint)

	// Add query parameters for package_name and package_type
	q := u.Query()
	q.Set("package_name", packageName)
	q.Set("package_type", ecosystem)
	u.RawQuery = q.Encode()

	return u, nil
}

// Response is the response from the package intelligence API
type Response struct {
	PackageName  string       `json:"package_name"`
	PackageType  string       `json:"package_type"`
	Summary      ScoreSummary `json:"summary"`
	Alternatives struct {
		Status   string        `json:"status"`
		Packages []Alternative `json:"packages"`
	} `json:"alternatives"`
}

// Alternative is an alternative package returned from the package intelligence API
type Alternative struct {
	PackageName    string  `json:"package_name"`
	Score          float64 `json:"score"`
	PackageNameURL string
}

// ScoreSummary is the summary score returned from the package intelligence API
type ScoreSummary struct {
	Score       float64        `json:"score"`
	Description map[string]any `json:"description"`
}
