package packages

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/google/uuid"
	v1 "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"

	"sigs.k8s.io/release-sdk/git"
	"sigs.k8s.io/release-utils/util"
)

type Ecosystem string

const (
	Python Ecosystem = "python"
	Go     Ecosystem = "go"
	Npm    Ecosystem = "npm"
)

func (e Ecosystem) ToTrusty() v1.DepEcosystem {
	switch e {
	case Python:
		return v1.DepEcosystem_DEP_ECOSYSTEM_PYPI
	case Go:
		return v1.DepEcosystem_DEP_ECOSYSTEM_GO
	case Npm:
		return v1.DepEcosystem_DEP_ECOSYSTEM_NPM
	}
	return 0
}

type Lister struct{}

func NewLister() *Lister {
	return &Lister{}
}

// GuessEcosystem looks at a directory and tries to guess what kind of code lives
// there.
func (l *Lister) GuessEcosystem(path string) (Ecosystem, error) {
	if !util.Exists(path) {
		return "", fmt.Errorf("specified directory doesn't exist")
	}

	switch {
	case util.Exists(filepath.Join(path, "requirements.txt")):
		return Python, nil
	case util.Exists(filepath.Join(path, "go.mod")):
		return Go, nil
	case util.Exists(filepath.Join(path, "package-lock.json")):
		return Npm, nil
	default:
		return "", nil
	}
}

// ReadPackages extracts the dependencies of a project
func (l *Lister) ReadPackages(ctx context.Context, path string) (*sbom.NodeList, error) {
	ecosystem, err := l.GuessEcosystem(path)
	if err != nil {
		return nil, fmt.Errorf("reading packages: %w", err)
	}

	cataloger := getCataloger(ecosystem)
	if cataloger == nil {
		return nil, fmt.Errorf("ecosystem no yet supported")
	}

	solver, err := getResolver(path)
	if err != nil {
		return nil, err
	}

	name, err := getProjectName(path)
	if err != nil {
		return nil, err
	}

	packages, _, err := cataloger.Catalog(ctx, solver)
	if err != nil {
		return nil, fmt.Errorf("scanning for packages: %w", err)
	}

	nodeList := sbom.NewNodeList()

	rootNode := sbom.NewNode()
	rootNode.Name = name
	rootNode.Id = "root"
	nodeList.AddRootNode(rootNode)
	deduper := map[string]map[string]struct{}{}
	for _, p := range packages {
		if _, ok := deduper[p.Name]; ok {
			if _, ok := deduper[p.Name][p.Version]; ok {
				continue
			}
		} else {
			deduper[p.Name] = map[string]struct{}{}
		}
		node := sbom.NewNode()
		node.Id = uuid.NewString()
		node.Name = p.Name
		node.Version = p.Version
		if len(p.CPEs) >= 1 {
			node.Identifiers[int32(sbom.SoftwareIdentifierType_CPE23)] = p.CPEs[0].Source.String()
		}
		node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = p.PURL
		for _, l := range p.Licenses.ToSlice() {
			node.Licenses = append(node.Licenses, l.SPDXExpression)
		}
		deduper[p.Name][p.Version] = struct{}{}
		nodeList.RelateNodeAtID(node, "root", sbom.Edge_dependsOn)
	}

	return nodeList, nil
}

func getCataloger(e Ecosystem) pkg.Cataloger {
	switch e {
	case Python:
		return python.NewInstalledPackageCataloger()
	case Go:
		return golang.NewGoModuleFileCataloger(golang.DefaultCatalogerConfig())
	case Npm:
		return javascript.NewLockCataloger(javascript.DefaultCatalogerConfig())
	default:
		return nil
	}
}

func getResolver(path string) (file.Resolver, error) {
	src, err := directorysource.NewFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("creating directory source: %w", err)
	}

	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		return nil, fmt.Errorf("creating resolver: %w", err)
	}

	return resolver, nil
}

// getProjectName
func getProjectName(path string) (string, error) {
	r, err := git.OpenRepo(path)
	if err != nil {
		return "", err
	}
	remotes, err := r.Remotes()
	if err != nil {
		return "", err
	}

	for _, r := range remotes {
		if r.Name() == "origin" {
			if len(r.URLs()) > 0 {
				return r.URLs()[0], nil
			}
		}
	}

	return "", nil
}
