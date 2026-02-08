package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"
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

	getUserData()

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
				log.Println("cycle execute got an error:", err)
			}
		}
	}
}

func getUserData() {
	in, err := LoadInputFile("input.json")
	if err != nil {
		log.Fatal(err)
	}

	principals := ExtractPrincipals(in)
	for _, p := range principals {
		subjects := SubjectsForPrincipal(p)
		fmt.Println(p.Username, subjects)
	}
}

// running one full RBAC access collection + reporting cycle
func executeRbacAccessCycle(ctx context.Context, kubernetesClient *kubernetes.Clientset) error {
	//runCtx, cancel := context.WithTimeout(ctx, 30*time.Second) // for production
	runCtx, cancel := context.WithCancel(ctx) //for debugging
	defer cancel()

	//getting role binding and cluster role binding list from kubernetes api server
	crbs, rbs, clusterRoles, roles, err := receiveLogsFromApiServer(runCtx, kubernetesClient)
	if err != nil {
		return fmt.Errorf("can not get the role binding list from kubernetes api server: %w", err)
	}
	//fmt.Printf("crbs=%+v\n", *crbs)
	//fmt.Printf("rbs=%+v\n", *rbs)
	records := processLogs(crbs, rbs, clusterRoles, roles)
	printReport(records)

	return nil
}

func printReport(records []Access) {
	now := time.Now().Format(time.RFC3339)
	fmt.Printf("\n --- RBAC access report @ %s ---\n", now)
	fmt.Printf("total bindings resolved to subject mappings: %d\n", len(records))

	bySubject := map[string][]Access{}
	keys := make([]string, 0)

	for _, record := range records {
		subKey := fmt.Sprintf("%s/%s", record.kind, record.name)
		if record.kind == "ServiceAccount" && record.namespace != "" {
			subKey = fmt.Sprintf("%s:%s/%s", record.kind, record.namespace, record.name)
		}
		if _, ok := bySubject[subKey]; !ok {
			keys = append(keys, subKey)
		}
		bySubject[subKey] = append(bySubject[subKey], record)
	}

	sort.Strings(keys)

	for _, k := range keys {
		fmt.Printf("\n - %s\n", k)
		for _, r := range bySubject[k] {
			fmt.Printf("  - scope=%s roleRef=%s/%s binding=%s\n", r.namespaced, r.roleRefKind, r.roleRefName, r.binding)
		}
	}
}

func processLogs(crbs *rbacv1.ClusterRoleBindingList, rbs *rbacv1.RoleBindingList,
	clusterRoles *rbacv1.ClusterRoleList, roles *rbacv1.RoleList) []Access {
	records := make([]Access, 0, len(crbs.Items)+len(rbs.Items)) //creating the accesses list

	for _, b := range crbs.Items {
		records = append(records, bindingToRecordsCluster(b)...)
	}
	for _, b := range rbs.Items {
		records = append(records, bindingToRecordsNamespaced(b)...)
	}

	// implementation of sort function
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		if a.name != b.name {
			return a.name < b.name
		}
		if a.namespaced != b.namespaced {
			return a.namespace < b.namespace
		}
		if a.roleRefKind != b.roleRefKind {
			return a.roleRefKind < b.roleRefKind
		}
		return a.roleRefName < b.roleRefName
	})
	return records
}

func bindingToRecordsCluster(b rbacv1.ClusterRoleBinding) []Access {
	out := make([]Access, 0, len(b.Subjects))
	for _, s := range b.Subjects { // in ghesmat mitoone tamiz tar bashe WARN
		out = append(out, Access{
			kind:        s.Kind,
			name:        s.Name,
			namespace:   s.Namespace,
			namespaced:  false, // these are cluster scope accesses
			roleRefKind: b.RoleRef.Kind,
			roleRefName: b.RoleRef.Name,
			binding:     "ClusterRoleBinding/" + b.Name,
		})
	}
	//fmt.Printf("out is: %s\n", out)
	return out
}

func bindingToRecordsNamespaced(b rbacv1.RoleBinding) []Access {
	//scope := "namespaced" + b.Namespace
	out := make([]Access, 0, len(b.Subjects))

	for _, s := range b.Subjects {
		out = append(out, Access{
			kind:        s.Kind,
			name:        s.Name,
			namespace:   pickNamespaceForSubject(s, b.Namespace),
			namespaced:  true, // these are namespaces accesses
			roleRefKind: b.RoleRef.Kind,
			roleRefName: b.RoleRef.Name,
			binding:     "RoleBinding/" + b.Namespace + "/" + b.Name,
		})
	}
	//fmt.Printf("out is: %s\n", out)
	return out
}

func pickNamespaceForSubject(s rbacv1.Subject, bindingNamespace string) string {
	// For ServiceAccount subjects, namespace may be omitted; then it means binding’s namespace.
	if strings.EqualFold(s.Kind, "ServiceAccount") {
		if s.Namespace == "" {
			return s.Namespace
		}
		return bindingNamespace
	}
	return s.Namespace
}

// fetching the RBAC binding from the kubernetes api server
func receiveLogsFromApiServer(ctx context.Context, client *kubernetes.Clientset) (*rbacv1.ClusterRoleBindingList, *rbacv1.RoleBindingList, *rbacv1.ClusterRoleList, *rbacv1.RoleList, error) {

	opts := metav1.ListOptions{}
	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, opts)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("can not get the cluster role binding list from cluster: %w", err)
	}

	// "" means all namespaces
	rbs, err := client.RbacV1().RoleBindings("").List(ctx, opts)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("can not get the role binding list from cluster: %w", err)
	}

	clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, opts)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("can not get the cluster role list from cluster: %w", err)
	}

	roles, err := client.RbacV1().Roles("").List(ctx, opts)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("can not get the role list from cluster: %w", err)
	}

	return crbs, rbs, clusterRoles, roles, nil
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
