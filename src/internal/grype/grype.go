package grype

type GrypeResult struct {
	Matches []GrypeMatch `json:"matches"`
}

type GrypeMatch struct {
	Vulnerability GrypeVulnerability `json:"vulnerability"`
	Artifact      GrypeArtifact      `json:"artifact"`
}

type GrypeVulnerability struct {
	Id          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Fix         GrypeFix `json:"fix"`
}

type GrypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type GrypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}
