package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sandrolain/gomsvc/pkg/datalib"
	"github.com/sandrolain/gomsvc/pkg/gitlib"
	"github.com/sandrolain/gomsvc/pkg/svc"
	"github.com/sandrolain/podsec-monitor/src/internal/grype"
	"github.com/sandrolain/podsec-monitor/src/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	svc.Service(svc.ServiceOptions{
		Name:    "podsec-monitor",
		Version: "1.0.0",
	}, func(cfg models.Config) {
		outPath := cfg.WorkdirPath
		namespaces := cfg.Namespaces
		minSeverity := cfg.MinSeverity

		nsSet := datalib.NewSet[string]()
		nsSet.Append(namespaces...)

		dirName := time.Now().Format("20060102_150405")
		dirPath := path.Join(outPath, dirName)
		svc.PanicIfError(os.MkdirAll(dirPath, os.ModePerm))

		l := svc.Logger()

		config, err := rest.InClusterConfig()

		if err == rest.ErrNotInCluster {
			var kubeconfig *string
			if home := homedir.HomeDir(); home != "" {
				kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
			} else {
				kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
			}
			flag.Parse()
			config = svc.PanicWithError(clientcmd.BuildConfigFromFlags("", *kubeconfig))
		} else {
			svc.PanicIfError(err)
		}

		clientset := svc.PanicWithError(kubernetes.NewForConfig(config))

		pods := svc.PanicWithError(clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{}))

		l.Info("Namespaces to process", "namespaces", namespaces)
		l.Info("Pods in the cluster", "num", len(pods.Items))

		images := datalib.NewSet[string]()

		results := []grype.Result{}

		for _, pod := range pods.Items {
			for _, cnt := range pod.Spec.Containers {
				if nsSet.Contains(pod.Namespace) {
					image := cnt.Image
					l.Info("Container", "pod", pod.Name, "container", cnt.Name, "image", image)

					if images.Contains(image) {
						l.Info("Image already processed", "image", image)
					} else {
						l.Info("Processing image", "image", image)

						fileName := svc.PanicWithError(datalib.SafeFilename(image, "json"))
						filePath := path.Join(dirPath, fileName)

						res, err := AnalyzeImage(image, filePath)

						if err != nil {
							svc.Error("Error Analyze with Grype", err, "image", image, "filePath", filePath)
							continue
						}

						vulNum := len(res.Matches)

						l.Info("Image processed", "image", image, "vulnerabilities", vulNum)

						// if vulNum > 0 {
						// 	devlib.P(res)
						// }
						results = append(results, res)
					}
					images.Add(image)
				}
			}
		}

		totalVul := 0
		for _, res := range results {
			totalVul += len(res.Matches)
		}

		l.Info("Finished", "totalImages", len(results), "totalVulnerabilities", totalVul)

		severityScores := map[string]int{
			"Unknown":    0,
			"Negligible": 1,
			"Low":        2,
			"Medium":     3,
			"High":       4,
			"Critical":   5,
		}

		severityEmojii := map[string]string{
			"Unknown":    "❓",
			"Negligible": "ℹ️",
			"Low":        "🩹",
			"Medium":     "⚠️",
			"High":       "🚨",
			"Critical":   "🔥",
		}

		tables := make([]string, len(results))

		for i, result := range results {
			matches := result.Matches

			sort.Slice(matches, func(i, j int) bool {
				if matches[i].Vulnerability.Severity == matches[j].Vulnerability.Severity {
					return matches[i].Vulnerability.Id < matches[j].Vulnerability.Id
				}
				return severityScores[matches[i].Vulnerability.Severity] > severityScores[matches[j].Vulnerability.Severity]
			})

			matches = slices.DeleteFunc(matches, func(match grype.Match) bool {
				sev := severityScores[match.Vulnerability.Severity]
				return sev < minSeverity
			})

			table := fmt.Sprintf(`
			<h3>%s<br>%s</h3>
			<table class="data-table"><thead>
				<tr><th>Severity</th><th>Vul ID</th><th>Package</th><th>Version</th><th>Type</th></tr>
			</thead><tbody>`, result.Source.Target.UserInput, result.Source.Target.ImageID)

			for _, res := range matches {
				severity := res.Vulnerability.Severity
				emo := severityEmojii[severity]

				table += fmt.Sprintf("<tr><td>%s %s</td>", emo, html.EscapeString(severity))
				table += fmt.Sprintf("<td><a href=\"%s\">%s</a></td>", html.EscapeString(res.Vulnerability.DataSource), html.EscapeString(res.Vulnerability.Id))
				table += fmt.Sprintf("<td>%s</td>", html.EscapeString(res.Artifact.Name))
				table += fmt.Sprintf("<td>%s</td>", html.EscapeString(res.Artifact.Version))
				table += fmt.Sprintf("<td>%s</td></tr>", html.EscapeString(res.Artifact.Type))
			}

			table += "</tbody></table>"

			tables[i] = table
		}

		reportTables := MailHtml(strings.Join(tables, ""))

		os.WriteFile("report.html", []byte(reportTables), 0644)

		svc.Exit(0)
	})

}

func MailHtml(body string) string {
	return `
	<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
	<html xmlns="http://www.w3.org/1999/xhtml">
	<head>
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
		<style type="text/css" rel="stylesheet" media="all">
		*:not(br):not(tr):not(html) {
			font-family: Arial, 'Helvetica Neue', Helvetica, sans-serif;
			-webkit-box-sizing: border-box;
			box-sizing: border-box;
		}
		body {
			width: 100% !important;
			height: 100%;
			margin: 0;
			line-height: 1.4;
			background-color: #FFFFFF;
			-webkit-text-size-adjust: none;
			font-size: 12px;
		}
		a {
			color: #3869D4;
		}
		h3 {
			font-size: 14px
		}
		.data-table {
			font-size: 12px;
      width: 100%;
      margin: 0;
      border-spacing: 0;
      border-collapse: collapse;
			background-color: #FFFFFF;
    }
    .data-table th {
      text-align: left;
      padding: 0px 5px;
      padding-bottom: 8px;
      border-bottom: 1px solid #EDEFF2;
    }
    .data-table td {
      padding: 10px 5px;
      font-size: 12px;
      line-height: 12px;
      border: 1px solid #EDEFF2;
      white-space: nowrap;
    }
    .data-table tr:nth-child(odd) td {
      background-color: #F4F4F7;
    }
		</style>
		<table class="email-body_inner" align="center" width="570" cellpadding="0" cellspacing="0">
    <tr><td>` + body + `</td></tr></table>
		</body>
		</html>
		`

}

func AnalyzeImage(image string, filePath string) (res grype.Result, err error) {
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

	res, err = LoadGrypeJson(filePath)
	return
}

func LoadGrypeJson(filePath string) (res grype.Result, err error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &res)
	return
}

func AnalyzeRepository(r gitlib.GitRef, workpath string, filePath string) (res grype.Result, err error) {
	repoDir, err := gitlib.Clone(r, workpath)
	if err != nil {
		return
	}
	return AnalyzeImage(fmt.Sprintf("dir:%s", repoDir), filePath)
}
