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

type EsAggBucket struct {
	Key      any   `json:"key"`
	DocCount int64 `json:"doc_count"`
}

type EsTermsAgg struct {
	Buckets []EsAggBucket `json:"buckets"`
}

type EsAggResp struct {
	Aggregations map[string]json.RawMessage `json:"aggregations"`
}

var (
	flatDocsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "rbac_flat_docs_total",
		Help: "Number of RBAC flat permission documents in the window.",
	})

	usersTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "rbac_users_total",
		Help: "Number of distinct usernames seen in the window.",
	})

	permissionGrants = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rbac_permission_grants_total",
		Help: "Count of permissions by namespace/resource/verb/scope in the window.",
	}, []string{"namespace", "resource", "verb", "scope"})

	highRiskGrants = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rbac_high_risk_grants_total",
		Help: "Count of high-risk permissions (create/update/patch/delete) by namespace/resource/verb/scope in the window.",
	}, []string{"namespace", "resource", "verb", "scope"})

	scrapeErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "rbac_exporter_scrape_errors_total",
		Help: "Total number of exporter scrape/update errors.",
	})

	lastSuccessUnix = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "rbac_exporter_last_success_unixtime",
		Help: "Unix timestamp of last successful metrics refresh.",
	})
)

func init() {
	prometheus.MustRegister(flatDocsTotal, usersTotal, permissionGrants, highRiskGrants, scrapeErrors, lastSuccessUnix)
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
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("response:%s: status:%s", resp.Status, string(b))
	}
	return b, nil
}

func main() {
	fmt.Printf("starting RBAC exporter app\n")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	esURL := getenv("ELASTICSEARCH_URL", "http://localhost:9200")
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
				scrapeErrors.Inc()
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
	permissionGrants.Reset()
	highRiskGrants.Reset()

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
		flatDocsTotal.Set(float64(parsed.Hits.Total.Value))
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
		usersTotal.Set(parsed.Aggregations["u"].Value)
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

		aggs, _ := root["aggregations"].(map[string]any)
		nsAgg, _ := aggs["ns"].(map[string]any)
		nsBuckets, _ := nsAgg["buckets"].([]any)

		highRisk := map[string]bool{"create": true, "update": true, "patch": true, "delete": true}

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
					scopeAgg := vbm["scope"].(map[string]any)
					scopeBuckets := scopeAgg["buckets"].([]any)

					for _, sb := range scopeBuckets {
						sbm := sb.(map[string]any)
						scope := fmt.Sprint(sbm["key"])
						count := sbm["doc_count"].(float64)

						permissionGrants.WithLabelValues(ns, res, verb, scope).Set(count)
						if highRisk[verb] {
							highRiskGrants.WithLabelValues(ns, res, verb, scope).Set(count)
						}
					}
				}
			}
		}
	}

	lastSuccessUnix.Set(float64(time.Now().Unix()))
	return nil
}
