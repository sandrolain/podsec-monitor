package grype

type Result struct {
	Matches []Match `json:"matches"`
	Target  Target  `json:"target"`
}

type ImageResult struct {
	Matches []Match     `json:"matches"`
	Source  ImageSource `json:"source"`
}

type ImageSource struct {
	Type   string `json:"type"`
	Target Target `json:"target"`
}

type DirResult struct {
	Matches []Match   `json:"matches"`
	Source  DirSource `json:"source"`
}

type DirSource struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

type Target struct {
	UserInput string `json:"userInput"`
	ImageID   string `json:"imageID"`
	ImageSize int64  `json:"imageSize"`
}

type Match struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	Artifact      Artifact      `json:"artifact"`
}

type Vulnerability struct {
	Id          string `json:"id"`
	DataSource  string `json:"dataSource"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Fix         Fix    `json:"fix"`
}

type Fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type Artifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}
