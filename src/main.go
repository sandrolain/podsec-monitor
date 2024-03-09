package main

import (
	"context"
	"flag"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sandrolain/gomsvc/pkg/datalib"
	"github.com/sandrolain/gomsvc/pkg/svc"
	"github.com/sandrolain/podsec-monitor/src/internal/cache"
	"github.com/sandrolain/podsec-monitor/src/internal/grype"
	"github.com/sandrolain/podsec-monitor/src/internal/mail"
	"github.com/sandrolain/podsec-monitor/src/internal/severity"
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
		l := svc.Logger()

		namespaces := cfg.Namespaces
		cacheTime := cfg.CacheTime

		outPath := svc.PanicWithError(filepath.Abs(cfg.WorkdirPath))
		l.Debug("Output path", "path", outPath)

		resultFiles := []string{}
		results := []grype.Result{}

		dirName := time.Now().Format("20060102_150405")
		dirPath := path.Join(outPath, dirName)
		svc.PanicIfError(os.MkdirAll(dirPath, os.ModePerm))

		cachePath := path.Join(outPath, "cache")
		l.Debug("Cache path", "path", cachePath)

		procCache := svc.PanicWithError(cache.Init(cachePath))

		processedImages := map[string]string{}

		if len(namespaces) > 0 {
			nsSet := datalib.NewSet[string]()
			nsSet.Append(namespaces...)

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

			for _, pod := range pods.Items {
				for _, cnt := range pod.Spec.Containers {
					if nsSet.Contains(pod.Namespace) {
						image := cnt.Image

						imageID := ""
						for _, sts := range pod.Status.ContainerStatuses {
							if sts.Name == cnt.Name {
								imageID = sts.ImageID
							}
						}

						if imageID == "" {
							imageID = image
						}

						imageID = strings.Replace(imageID, "docker-pullable://", "", -1)

						l.Info("Container", "pod", pod.Name, "container", cnt.Name, "image", image, "imageID", imageID)

						if _, proc := processedImages[imageID]; proc {
							l.Info("Image already processed", "image", image, "imageID", imageID)
						} else {
							res, filePath, err := ProcessImage(dirPath, procCache, cacheTime, imageID, image, processedImages)
							if err != nil {
								svc.Error("Failed to process image", err, "image", image, "imageID", imageID)
							} else {
								results = append(results, res)
								resultFiles = append(resultFiles, filePath)
							}
						}
					}
				}
			}

			l.Info("All images processed", "num", len(results))
		}

		if len(cfg.Directories) > 0 {
			for _, dir := range cfg.Directories {
				image := "dir:" + path.Join(outPath, dir)
				imageID := image
				res, filePath, err := ProcessImage(dirPath, procCache, cacheTime, imageID, image, processedImages)
				if err != nil {
					svc.Error("Failed to process directory", err, "directory", dir)
				} else {
					results = append(results, res)
					resultFiles = append(resultFiles, filePath)
				}
			}
		}

		mailResults := []mail.MailResult{}

		for _, result := range results {
			matches := result.Matches

			sort.Slice(matches, func(i, j int) bool {
				if matches[i].Vulnerability.Severity == matches[j].Vulnerability.Severity {
					return matches[i].Vulnerability.Id < matches[j].Vulnerability.Id
				}
				return severity.GetSeverityIndex(matches[i].Vulnerability.Severity) > severity.GetSeverityIndex(matches[j].Vulnerability.Severity)
			})

			matches = slices.DeleteFunc(matches, func(match grype.Match) bool {
				return severity.GetSeverityIndex(match.Vulnerability.Severity) < cfg.MinSeverity
			})

			rest := 0
			if cfg.VulnLimit > 0 && len(matches) > cfg.VulnLimit {
				rest = len(matches) - cfg.VulnLimit
				matches = matches[:cfg.VulnLimit]
			}

			result.Matches = matches

			if len(matches) == 0 {
				continue
			}

			mailResults = append(mailResults, mail.MailResult{
				Rest:   rest,
				Result: result,
			})
		}

		if len(mailResults) > 0 {
			totalVul := 0
			for _, res := range results {
				totalVul += len(res.Matches)
			}

			l.Info("Finished", "totalImages", len(results), "totalVulnerabilities", totalVul)

			html, err := mail.GenerateMail(cfg, mailResults, processedImages)
			if err != nil {
				svc.Error("Error generating email", err)
			} else {
				err = mail.SendEmail(mail.SendMailArgs{
					Subject:  "Podsec Report",
					Body:     html,
					To:       cfg.SmtpTo,
					From:     cfg.SmtpFrom,
					Host:     cfg.SmtpHost,
					Port:     cfg.SmtpPort,
					Username: cfg.SmtpUsername,
					Password: cfg.SmtpPassword,
					Files:    resultFiles,
				})
				if err != nil {
					svc.Error("Error sending email", err)
				}
			}
		} else {
			l.Info("No new vulnerabilities")
		}

		os.RemoveAll(dirPath)

		svc.Exit(0)
	})

}

func ProcessImage(dirPath string, procCache *cache.Cache, cacheTime uint32, imageID string, image string, processedImages map[string]string) (res grype.Result, filePath string, err error) {
	l := svc.Logger()
	cacheVal, err := procCache.Get(imageID)
	if err == nil && cacheVal != "" {
		l.Info("Resource already in cache", "image", image, "imageID", imageID)
		processedImages[imageID] = image
		return
	}

	l.Info("Processing resource", "resource", image)

	fileName := svc.PanicWithError(datalib.SafeFilename(imageID, "json"))
	filePath = path.Join(dirPath, fileName)

	res, err = grype.Analyze(imageID, filePath)

	if err != nil {
		svc.Error("Error Analyze with Grype", err, "image", image, "imageID", imageID, "filePath", filePath)
		return
	}

	vulNum := len(res.Matches)

	l.Info("Image processed", "image", image, "imageID", imageID, "vulnerabilities", vulNum)

	processedImages[imageID] = image

	if err := procCache.Set(imageID, image, cacheTime); err != nil {
		svc.Error("Error cache image", err, "image", image, "imageID", imageID)
	}
	return
}
