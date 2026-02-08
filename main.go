package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type Access struct {
	kind        string
	name        string
	namespace   string
	namespaced  bool
	roleRefKind string
	roleRefName string
	binding     string
}

func main() {
	var (
		interval = flag.Duration("interval", 5*time.Minute, "Polling interval (e.g. 5m)")
	)
	flag.Parse()
	println("audit log app has been started")

	kubernetesClient, err := buildKubernetesClient()
	if err != nil {
		log.Fatalln("failed to build kubernetes client from the kube config")
	}

	ctx := context.Background()

	if err := executeRbacAccessCycle(ctx, kubernetesClient); err != nil {
		log.Println("failed to execute rbac access cycle:", err)
	}

	ticket := time.NewTicker(*interval)
	defer ticket.Stop()

	for {
		select {
		case <-ticket.C:
			if err := executeRbacAccessCycle(ctx, kubernetesClient); err != nil {
				log.Println("one cycle is getting executed with error:", err)
			}
		}
	}
}

// running one full RBAC access collection + reporting cycle
func executeRbacAccessCycle(ctx context.Context, kubernetesClient *kubernetes.Clientset) error {
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	//getting role binding and cluster role binding list from kubernetes api server
	crbs, rbs, err := receiveLogsFromApiServer(runCtx, kubernetesClient)
	if err != nil {
		return fmt.Errorf("can not get the role binding list from kubernetes api server: %w", err)
	}
	fmt.Printf("crbs=%+v\n", *crbs)
	fmt.Printf("rbs=%+v\n", *rbs)
	//records := processLogs(crbs, rbs)
	//printReport(records)

	return nil
}

// fetching the RBAC binding from the kubernetes api server
func receiveLogsFromApiServer(ctx context.Context, client *kubernetes.Clientset) (*rbacv1.ClusterRoleBindingList, *rbacv1.RoleBindingList, error) {

	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("can not get the role binding list from kubernetes api server: %w", err)
	}

	// "" means all namespaces
	rbs, err := client.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("can not get the role binding list from kubernetes api server: %w", err)
	}

	return crbs, rbs, nil
}

func buildKubernetesClient() (*kubernetes.Clientset, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return kubernetes.NewForConfig(cfg)
	}

	home := homedir.HomeDir()
	// path to the kube config
	kubeconfigPath := filepath.Join(home, ".kube", "config")

	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}
