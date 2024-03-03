package osv

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/sandrolain/gomsvc/pkg/devlib"
	"github.com/sandrolain/gomsvc/pkg/gitlib"
)

func AnalyzeRepositoryOSV(r gitlib.GitRef, workpath string) (res Result, err error) {
	repoDir, err := gitlib.Clone(r, workpath)
	if err != nil {
		return
	}

	devlib.P(repoDir)

	out, e := exec.Command("osv-scanner", "-r", "--format", "json", repoDir).Output()

	if e != nil && len(out) == 0 {
		err = fmt.Errorf("osv-scanner: %w", e)
		return
	}

	err = json.Unmarshal(out, &res)

	devlib.P(res)
	return
}

type Result struct {
	Results []ResultEntry `json:"results"`
}

type ResultEntry struct {
	Source   Source         `json:"source"`
	Packages []PackageEntry `json:"packages"`
}

type Source struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type PackageEntry struct {
	Package Package `json:"package"`
	Vulns   []Vuln  `json:"vulnerabilities"`
}

type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type Vuln struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Summary string   `json:"summary"`
	Details string   `json:"details"`
}
