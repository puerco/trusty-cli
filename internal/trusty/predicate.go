package trusty

import "time"

// TODO(puerco): Protobuf this

type Predicate struct {
	Date *time.Time
	PackageInfo
	Packages []PackageScore
}

type PackageInfo struct {
	Package     string
	Version     string
	Identifiers map[string]string
}

type PackageScore struct {
	PackageInfo
	Score   float64
	Details map[string]any
}
