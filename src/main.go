package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/sandrolain/gomsvc/pkg/datalib"
	"github.com/sandrolain/gomsvc/pkg/gitlib"
	"github.com/sandrolain/gomsvc/pkg/svc"
	"github.com/sandrolain/podsec-monitor/src/internal/cache"
	"github.com/sandrolain/podsec-monitor/src/internal/grype"
	"github.com/sandrolain/podsec-monitor/src/internal/mail"
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

		nsSet := datalib.NewSet[string]()
		nsSet.Append(namespaces...)

		dirName := time.Now().Format("20060102_150405")
		dirPath := path.Join(outPath, dirName)
		svc.PanicIfError(os.MkdirAll(dirPath, os.ModePerm))

		cachePath := path.Join(outPath, "cache")
		l.Debug("Cache path", "path", cachePath)

		procCache := svc.PanicWithError(cache.Init(cachePath))

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

		processedImages := map[string]string{}

		resultFiles := []string{}
		results := []grype.Result{}

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
						cacheVal, err := procCache.Get(imageID)
						if err == nil && cacheVal != "" {
							l.Info("Image already in cache", "image", image, "imageID", imageID)
							processedImages[imageID] = image
							continue
						}

						l.Info("Processing image", "image", image)

						fileName := svc.PanicWithError(datalib.SafeFilename(imageID, "json"))
						filePath := path.Join(dirPath, fileName)

						res, err := AnalyzeImage(imageID, filePath)

						if err != nil {
							svc.Error("Error Analyze with Grype", err, "image", image, "imageID", imageID, "filePath", filePath)
							continue
						}

						vulNum := len(res.Matches)

						l.Info("Image processed", "image", image, "imageID", imageID, "vulnerabilities", vulNum)

						results = append(results, res)
						resultFiles = append(resultFiles, filePath)

						processedImages[imageID] = image

						err = procCache.Set(imageID, image, cacheTime)

						if err != nil {
							svc.Error("Error cache image", err, "image", image, "imageID", imageID)
						}
					}
				}
			}
		}

		if len(results) == 0 {
			l.Info("No images scanned")
			svc.Exit(0)
		}

		totalVul := 0
		for _, res := range results {
			totalVul += len(res.Matches)
		}

		l.Info("Finished", "totalImages", len(results), "totalVulnerabilities", totalVul)

		html := svc.PanicWithError(mail.GenerateMail(cfg, results, processedImages))

		os.WriteFile("report.html", []byte(html), 0644)

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

		os.RemoveAll(dirPath)

		svc.Exit(0)
	})

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
