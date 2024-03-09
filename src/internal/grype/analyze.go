package grype

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/sandrolain/gomsvc/pkg/gitlib"
)

func Analyze(image string, filePath string) (res Result, err error) {
	cmd := exec.Command("grype", image, "-o", "json", "--file", filePath, "--add-cpes-if-none")
	cmdReader, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(cmdReader)
	go func() {
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()

	err = cmd.Start()
	if err != nil {
		return
	}

	err = cmd.Wait()
	if err != nil {
		return
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	if image[0:4] == "dir:" {
		dirRes := DirResult{}
		err = json.Unmarshal(data, &dirRes)
		if err != nil {
			return
		}
		res.Matches = dirRes.Matches
		res.Target = Target{
			UserInput: image,
			ImageID:   dirRes.Source.Target,
		}
	} else {
		imageRes := ImageResult{}
		err = json.Unmarshal(data, &imageRes)
		if err != nil {
			return
		}
		res.Matches = imageRes.Matches
		res.Target = imageRes.Source.Target
	}

	return
}

func AnalyzeRepository(r gitlib.GitRef, workpath string, filePath string) (res Result, err error) {
	repoDir, err := gitlib.Clone(r, workpath)
	if err != nil {
		return
	}
	res, err = Analyze(fmt.Sprintf("dir:%s", repoDir), filePath)
	return
}
