package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"

	"github.com/sandrolain/gomsvc/pkg/datalib"
	"github.com/sandrolain/gomsvc/pkg/devlib"
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
		fmt.Printf("cfg: %v\n", cfg)

		// TODO: configs
		outPath := "./out"
		namespaces := []string{"default"}
		//

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

		l.Info("Pods in the cluster", "num", len(pods.Items))

		images := datalib.NewSet[string]()

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

						err := exec.Command("grype", image, "-o", "json", "--file", filePath, "--add-cpes-if-none").Run()
						if err != nil {
							svc.Error("grype", err, "image", image, "filePath", filePath)
							continue
						}

						res, err := LoadGrypeJson(filePath)
						if err != nil {
							svc.Error("Parse Grype JSON", err, "image", image, "filePath", filePath)
							continue
						}

						vulNum := len(res.Matches)

						l.Info("Image processed", "image", image, "vulnerabilities", vulNum)

						if vulNum > 0 {
							devlib.P(res)
						}

					}
					images.Add(image)
				}
			}
		}

		svc.Exit(0)
	})

}

func LoadGrypeJson(filePath string) (res grype.GrypeResult, err error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, &res)
	return
}
