package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	sensitiveAccessUsers = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "k8s_namespace_sensitive_access_users_count",
		Help: "Count of distinct users that have sensitive accesses (secrets, deployments, configmaps) for a verb in a resource in a namespace.",
	}, []string{"namespace", "verb", "resource"})

	clusterwideAccessUsers = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "k8s_clusterwide_sensitive_access_users_count",
		Help: "Count of distinct users that have cluster-wide access to important resources and verbs.",
	}, []string{"resource", "verb"})
)

func init() {
	prometheus.MustRegister(sensitiveAccessUsers, clusterwideAccessUsers)
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getenvDuration(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if dur, err := time.ParseDuration(v); err == nil {
			return dur
		}
	}
	return d
}

func getenvInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func esDo(ctx context.Context, client *http.Client, baseURL,
	esUser, esPass, path string, body []byte) ([]byte, error) {
	u := strings.TrimRight(baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if esUser != "" || esPass != "" {
		req.SetBasicAuth(esUser, esPass)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(resp.Body)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("response:%s: status:%s", resp.Status, string(b))
	}
	return b, nil
}

func main() {
	fmt.Printf("starting RBAC exporter app\n")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	esURL := getenv("ELASTICSEARCH_URL", "https://elasticsearch.mahdixak.ir/")
	esUser := os.Getenv("ES_USERNAME")
	esPass := os.Getenv("ES_PASSWORD")

	index := getenv("ES_INDEX", "audit-logs-flat")
	window := getenvDuration("WINDOW", 24*time.Hour)
	pollEvery := getenvDuration("POLL_EVERY", 30*time.Second)
	maxBuckets := getenvInt("MAX_BUCKETS", 10)

	client := &http.Client{Timeout: 20 * time.Second}
	ctx := context.Background()

	//refresh loop
	go func() {
		for {
			if err := refreshOnce(ctx, client, esURL, esUser, esPass, index, window, maxBuckets); err != nil {
				log.Printf("failed to refresh buckets: %v", err)
			} else {
				log.Printf("buckets refreshed in index:%s and window:%s", index, window)
			}
			time.Sleep(pollEvery)
		}
	}()

	//metrics endpoints
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	addr := getenv("LISTEN_ADDR", ":8080")
	log.Printf("exporter listening on %s/metrics", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen error: %v", err)
	}
}

func refreshOnce(ctx context.Context, client *http.Client, url string, user string, pass string, index string, window time.Duration, buckets int) error {
	now := time.Now()
	gte := now.Add(-window).Format(time.RFC3339)

	//reseting gauges to avoid stale label sets
	sensitiveAccessUsers.Reset()
	clusterwideAccessUsers.Reset()

	// total docs in window
	{
		q := map[string]any{
			"size": 0,
			"query": map[string]any{
				"range": map[string]any{
					"@timestamp": map[string]any{
						"gte": gte,
						"lte": now.Format(time.RFC3339),
					},
				},
			},
		}
		body, _ := json.Marshal(q)

		respBody, err := esDo(ctx, client, url, user, pass, "/"+index+"/_search", body)
		if err != nil {
			return fmt.Errorf("docs count query: %w", err)
		}

		var parsed struct {
			Hits struct {
				Total struct {
					Value int64 `json:"value"`
				} `json:"total"`
			} `json:"hits"`
		}
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return fmt.Errorf("docs count decode: %w", err)
		}
	}

	// 2) distinct users in window (cardinality agg)
	{
		q := map[string]any{
			"size": 0,
			"query": map[string]any{
				"range": map[string]any{
					"@timestamp": map[string]any{
						"gte": gte,
						"lte": now.Format(time.RFC3339),
					},
				},
			},
			"aggs": map[string]any{
				"u": map[string]any{
					"cardinality": map[string]any{
						"field": "username.keyword",
					},
				},
			},
		}
		body, _ := json.Marshal(q)
		respBody, err := esDo(ctx, client, url, user, pass, "/"+index+"/_search", body)
		if err != nil {
			return fmt.Errorf("users cardinality query: %w", err)
		}

		var parsed struct {
			Aggregations map[string]struct {
				Value float64 `json:"value"`
			} `json:"aggregations"`
		}
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return fmt.Errorf("users cardinality decode: %w", err)
		}
	}

	// 3) grants by namespace/resource/verb/scope (terms aggs)
	{
		q := map[string]any{
			"size": 0,
			"query": map[string]any{
				"range": map[string]any{
					"@timestamp": map[string]any{
						"gte": gte,
						"lte": now.Format(time.RFC3339),
					},
				},
			},
			"aggs": map[string]any{
				"ns": map[string]any{
					"terms": map[string]any{"field": "namespace.keyword", "size": buckets},
					"aggs": map[string]any{
						"res": map[string]any{
							"terms": map[string]any{"field": "resource.keyword", "size": buckets},
							"aggs": map[string]any{
								"verb": map[string]any{
									"terms": map[string]any{"field": "verb.keyword", "size": buckets},
									"aggs": map[string]any{
										"scope": map[string]any{
											"terms": map[string]any{"field": "scope.keyword", "size": 10},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		body, _ := json.Marshal(q)
		respBody, err := esDo(ctx, client, url, user, pass, "/"+index+"/_search", body)
		if err != nil {
			return fmt.Errorf("grants agg query: %w", err)
		}

		// parse nested buckets
		var root map[string]any
		if err := json.Unmarshal(respBody, &root); err != nil {
			return fmt.Errorf("grants agg decode: %w", err)
		}
	}

	// 4) sensitive resource access: distinct users per namespace/resource/verb for secrets, deployments, configmaps.
	{
		q := map[string]any{
			"size": 0,
			"query": map[string]any{
				"bool": map[string]any{
					"must": []map[string]any{
						{
							"range": map[string]any{
								"@timestamp": map[string]any{
									"gte": gte,
									"lte": now.Format(time.RFC3339),
								},
							},
						},
						{
							"terms": map[string]any{
								"resource.keyword": []string{"secrets", "deployments", "configmaps"},
							},
						},
					},
				},
			},
			"aggs": map[string]any{
				"ns": map[string]any{
					"terms": map[string]any{"field": "namespace.keyword", "size": buckets},
					"aggs": map[string]any{
						"res": map[string]any{
							"terms": map[string]any{"field": "resource.keyword", "size": 3},
							"aggs": map[string]any{
								"verb": map[string]any{
									"terms": map[string]any{"field": "verb.keyword", "size": buckets},
									"aggs": map[string]any{
										"user_count": map[string]any{
											"cardinality": map[string]any{
												"field": "username.keyword",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		body, _ := json.Marshal(q)
		respBody, err := esDo(ctx, client, url, user, pass, "/"+index+"/_search", body)
		if err != nil {
			return fmt.Errorf("sensitive access query: %w", err)
		}

		var root map[string]any
		if err := json.Unmarshal(respBody, &root); err != nil {
			return fmt.Errorf("sensitive access decode: %w", err)
		}

		aggs, _ := root["aggregations"].(map[string]any)
		nsAgg, _ := aggs["ns"].(map[string]any)
		nsBuckets, _ := nsAgg["buckets"].([]any)

		for _, nb := range nsBuckets {
			nbm := nb.(map[string]any)
			ns := fmt.Sprint(nbm["key"])
			resAgg := nbm["res"].(map[string]any)
			resBuckets := resAgg["buckets"].([]any)

			for _, rb := range resBuckets {
				rbm := rb.(map[string]any)
				res := fmt.Sprint(rbm["key"])
				verbAgg := rbm["verb"].(map[string]any)
				verbBuckets := verbAgg["buckets"].([]any)

				for _, vb := range verbBuckets {
					vbm := vb.(map[string]any)
					verb := fmt.Sprint(vbm["key"])
					userCountAgg := vbm["user_count"].(map[string]any)
					userCount := userCountAgg["value"].(float64)

					sensitiveAccessUsers.WithLabelValues(ns, verb, res).Set(userCount)
				}
			}
		}
	}

	// 5) cluster-wide sensitive access: distinct users per resource/verb for important resources with cluster scope.
	{
		importantResources := []string{
			"secrets", "pods", "deployments", "daemonsets", "statefulsets",
			"configmaps", "nodes", "persistentvolumes", "clusterroles",
			"clusterrolebindings", "serviceaccounts", "namespaces",
		}
		importantVerbs := []string{
			"create", "update", "delete", "patch", "*",
		}

		q := map[string]any{
			"size": 0,
			"query": map[string]any{
				"bool": map[string]any{
					"must": []map[string]any{
						{
							"range": map[string]any{
								"@timestamp": map[string]any{
									"gte": gte,
									"lte": now.Format(time.RFC3339),
								},
							},
						},
						{
							"term": map[string]any{
								"scope.keyword": "cluster",
							},
						},
						{
							"terms": map[string]any{
								"resource.keyword": importantResources,
							},
						},
						{
							"terms": map[string]any{
								"verb.keyword": importantVerbs,
							},
						},
					},
				},
			},
			"aggs": map[string]any{
				"res": map[string]any{
					"terms": map[string]any{"field": "resource.keyword", "size": len(importantResources)},
					"aggs": map[string]any{
						"verb": map[string]any{
							"terms": map[string]any{"field": "verb.keyword", "size": len(importantVerbs)},
							"aggs": map[string]any{
								"user_count": map[string]any{
									"cardinality": map[string]any{
										"field": "username.keyword",
									},
								},
							},
						},
					},
				},
			},
		}

		body, _ := json.Marshal(q)
		respBody, err := esDo(ctx, client, url, user, pass, "/"+index+"/_search", body)
		if err != nil {
			return fmt.Errorf("clusterwide access query: %w", err)
		}

		var root map[string]any
		if err := json.Unmarshal(respBody, &root); err != nil {
			return fmt.Errorf("clusterwide access decode: %w", err)
		}

		aggs, _ := root["aggregations"].(map[string]any)
		resAgg, _ := aggs["res"].(map[string]any)
		resBuckets, _ := resAgg["buckets"].([]any)

		for _, rb := range resBuckets {
			rbm := rb.(map[string]any)
			res := fmt.Sprint(rbm["key"])
			verbAgg := rbm["verb"].(map[string]any)
			verbBuckets := verbAgg["buckets"].([]any)

			for _, vb := range verbBuckets {
				vbm := vb.(map[string]any)
				verb := fmt.Sprint(vbm["key"])
				userCountAgg := vbm["user_count"].(map[string]any)
				userCount := userCountAgg["value"].(float64)

				clusterwideAccessUsers.WithLabelValues(res, verb).Set(userCount)
			}
		}
	}

	return nil
}
