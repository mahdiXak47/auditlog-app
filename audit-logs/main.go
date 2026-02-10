package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type Access struct {
	kind        string // user group or serviceAccount
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

	inputPath := getEnv("INPUT_PATH", "../shared/json-files/input.json")
	in, err := LoadInputFile(inputPath)
	if err != nil {
		log.Fatal(err)
	}
	principals := ExtractPrincipals(in)

	kubernetesClient, err := buildKubernetesClient()
	if err != nil {
		log.Fatalln("failed to build kubernetes client from the kubeconfig")
	}

	ctx := context.Background()

	ticket := time.NewTicker(*interval)
	defer ticket.Stop()

	for {
		if err := executeRbacAccessCycle(ctx, kubernetesClient, principals); err != nil {
			log.Println("cycle execute got an error:", err)
		}
		<-ticket.C
	}
}

// running one full RBAC access collection + reporting cycle
func executeRbacAccessCycle(
	ctx context.Context, kubernetesClient *kubernetes.Clientset,
	principals []Principal) error {
	//runCtx, cancel := context.WithTimeout(ctx, 30*time.Second) // for production
	runCtx, cancel := context.WithCancel(ctx) //for debugging
	defer cancel()

	//getting role binding and cluster role binding list from kubernetes api server
	clusterRbs, rbs, clusterRoles, roles, namespaces, err := receiveLogsFromApiServer(runCtx, kubernetesClient)
	if err != nil {
		return fmt.Errorf("can not get the role binding list from kubernetes api server: %w", err)
	}
	//fmt.Printf("clusterRbs=%+v\n", *clusterRbs)
	//fmt.Printf("rbs=%+v\n", *rbs)
	records := getRoleBindingsList(clusterRbs, rbs)

	var namespaceList []string
	for _, ns := range namespaces.Items {
		namespaceList = append(namespaceList, ns.Name)
	}
	idx := buildRoleIndex(clusterRoles, roles)

	reports := BuildReportsForAllNamespaces(principals, records, idx, namespaceList)

	//printReport(records)
	outputPath := getEnv("OUTPUT_JSONL_PATH", "../shared/reports.jsonl")
	if err := PrintReportsAsJson(outputPath, reports); err != nil {
		return fmt.Errorf("printing the report as json got an error: %w", err)
	}

	flatPath := getEnv("OUTPUT_FLAT_JSONL_PATH", "../shared/reports-flat.jsonl")
	flat := FlattenReports(reports)
	if err := PrintFlatAsJsonL(flatPath, flat); err != nil {
		return fmt.Errorf("writing flat report: %w", err)
	}

	fmt.Printf("cycle complete: users=%d written to %s\n", len(reports), outputPath)
	return err
}

func PrintReportsAsJson(path string, reports []UserAccessReport) error {
	b, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		println(err.Error())
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(f)

	formatted := inlineVerbArrays(string(b))
	fmt.Println(formatted)

	debugOutputPath := getEnv("DEBUG_OUTPUT_PATH", "../shared/json-files/output-of-the-code.json")
	err = os.WriteFile(debugOutputPath, []byte(formatted), 0644)
	if err != nil {
		return fmt.Errorf("failed to write json output: %w", err)
	}

	enc := json.NewEncoder(f)

	for _, r := range reports {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

func PrintFlatAsJsonL(path string, rows []FlatPermission) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(f)

	enc := json.NewEncoder(f)
	for _, row := range rows {
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	return nil
}

func inlineVerbArrays(input string) string {
	re := regexp.MustCompile(`\[\n(\s+)"([^"]+)"(,\n\s+"[^"]+")*\n\s*]`)

	return re.ReplaceAllStringFunc(input, func(match string) string {
		// Remove newlines and spaces
		oneLine := strings.ReplaceAll(match, "\n", "")
		oneLine = strings.ReplaceAll(oneLine, "  ", "")
		oneLine = strings.ReplaceAll(oneLine, " ", "")
		return oneLine
	})
}

// fek konam esmesh bayad avaz beshe WARN
func getRoleBindingsList(crbs *rbacv1.ClusterRoleBindingList, rbs *rbacv1.RoleBindingList) []Access {
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
		if s.Namespace != "" {
			return s.Namespace
		}
		return bindingNamespace
	}
	return s.Namespace
}

// fetching the RBAC binding from the kubernetes api server
func receiveLogsFromApiServer(
	ctx context.Context, client *kubernetes.Clientset) (
	*rbacv1.ClusterRoleBindingList, *rbacv1.RoleBindingList,
	*rbacv1.ClusterRoleList, *rbacv1.RoleList, *corev1.NamespaceList, error) {

	opts := metav1.ListOptions{}
	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, opts)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("can not get the cluster role binding list from cluster: %w", err)
	}

	// "" means all namespaces
	rbs, err := client.RbacV1().RoleBindings("").List(ctx, opts)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("can not get the role binding list from cluster: %w", err)
	}

	clusterRoles, err := client.RbacV1().ClusterRoles().List(ctx, opts)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("can not get the cluster role list from cluster: %w", err)
	}

	roles, err := client.RbacV1().Roles("").List(ctx, opts)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("can not get the role list from cluster: %w", err)
	}

	namespaces, err := client.CoreV1().Namespaces().List(ctx, opts)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("can not get the namespace list from cluster: %w", err)
	}

	return crbs, rbs, clusterRoles, roles, namespaces, nil
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

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
