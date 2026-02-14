package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type BulkAction struct {
	Index map[string]string `json:"index"`
}

type BulkResp struct {
	Errors bool `json:"errors"`
	Items  []map[string]struct {
		Status int             `json:"status"`
		Error  json.RawMessage `json:"error,omitempty"`
	} `json:"items"`
}

func stableID(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

func writeOffsetAtomic(path string, v int64) error {
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, ".offset.tmp")
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(v, 10)), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	pollEvery := getenvDuration("POLL_EVERY", 1*time.Second)

	client := &http.Client{Timeout: 15 * time.Second}

	for {
		err := shipOnce(context.Background(), client)
		if err != nil {
			log.Printf("shipOnce error: %v", err)
			time.Sleep(5 * time.Second)
		} else {
			time.Sleep(pollEvery)
		}
	}
}
func shipFileOnce(
	ctx context.Context,
	client *http.Client,
	elasticSearchURL string,
	index string,
	dataPath string,
	offsetPath string,
	flushEvery int,
	esUser string,
	esPass string,
) error {

	off, offErr := readOffset(offsetPath)
	if offErr != nil && !os.IsNotExist(offErr) {
		log.Printf("readOffset warning for %s (starting from 0): %v", offsetPath, offErr)
		off = 0
	}

	f, err := os.Open(dataPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("data file not ready (will retry): %s", dataPath)
			return nil
		}
		return fmt.Errorf("open data file %s: %w", dataPath, err)
	}
	defer f.Close()

	// ✅ SAFETY: if file was truncated/rotated, reset offset
	if st, err := f.Stat(); err == nil {
		if off > st.Size() {
			log.Printf("offset %d > file size %d for %s; resetting to 0", off, st.Size(), dataPath)
			off = 0
		}
	}

	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return fmt.Errorf("seek to offset %d: %w", off, err)
	}

	r := bufio.NewReader(f)

	var (
		bulk bytes.Buffer
		n    int
	)

	flush := func(newOffset int64) error {
		if n == 0 {
			return nil
		}

		req, err := http.NewRequestWithContext(
			ctx,
			"POST",
			strings.TrimRight(elasticSearchURL, "/")+"/_bulk",
			bytes.NewReader(bulk.Bytes()),
		)
		if err != nil {
			return fmt.Errorf("create bulk request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-ndjson")
		if esUser != "" || esPass != "" {
			req.SetBasicAuth(esUser, esPass)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("bulk request failed: %w", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("bulk status=%s body=%s", resp.Status, string(body))
		}

		var br BulkResp
		if err := json.Unmarshal(body, &br); err != nil {
			return fmt.Errorf("bulk response decode error: %w body=%s", err, string(body))
		}
		if br.Errors {
			seen := 0
			for _, it := range br.Items {
				for _, v := range it {
					if v.Status >= 300 && seen < 5 {
						log.Printf("bulk item failed status=%d error=%s", v.Status, string(v.Error))
						seen++
					}
				}
			}
			return fmt.Errorf("bulk had partial errors")
		}

		if err := writeOffsetAtomic(offsetPath, newOffset); err != nil {
			return fmt.Errorf("write offset: %w", err)
		}

		log.Printf("flush success | index=%s docs=%d wroteOffset=%d", index, n, newOffset)

		bulk.Reset()
		n = 0
		return nil
	}

	for {
		startOffset, _ := f.Seek(0, io.SeekCurrent)
		line, err := r.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				// handle partial line without newline
				line = bytes.TrimSpace(line)
				if len(line) > 0 {
					var js any
					if e := json.Unmarshal(line, &js); e != nil {
						return fmt.Errorf("invalid json at offset %d: %w | line=%s", startOffset, e, string(line))
					}

					docID := stableID(line)
					action := BulkAction{Index: map[string]string{"_index": index, "_id": docID}}
					ab, _ := json.Marshal(action)

					bulk.Write(ab)
					bulk.WriteByte('\n')
					bulk.Write(line)
					bulk.WriteByte('\n')
					n++
				}

				endOffset, _ := f.Seek(0, io.SeekCurrent)
				return flush(endOffset)
			}
			return fmt.Errorf("read bytes: %w", err)
		}

		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var js any
		if err := json.Unmarshal(line, &js); err != nil {
			return fmt.Errorf("invalid json at offset %d: %w | line=%s", startOffset, err, string(line))
		}

		docID := stableID(line)
		action := BulkAction{Index: map[string]string{"_index": index, "_id": docID}}
		ab, _ := json.Marshal(action)

		bulk.Write(ab)
		bulk.WriteByte('\n')
		bulk.Write(line)
		bulk.WriteByte('\n')
		n++

		if n >= flushEvery {
			endOffset, _ := f.Seek(0, io.SeekCurrent)
			if err := flush(endOffset); err != nil {
				return err
			}
		}
	}
}

func shipOnce(ctx context.Context, client *http.Client) error {
	elasticSearchURL := getenv("ELASTICSEARCH_URL", "https://mahdixak-security-auditdb.darkube.app/")
	flushEvery := getenvInt("FLUSH_EVERY", 10)

	esUser := os.Getenv("ES_USERNAME")
	esPass := os.Getenv("ES_PASSWORD")

	// Pipeline 1: nested snapshot docs
	index := getenv("ELASTICSEARCH_INDEX", "audit-logs")
	dataPath := getenv("ELASTICSEARCH_DATA_PATH", "../shared/reports.jsonl")
	offsetPath := getenv("ELASTICSEARCH_OFFSET_PATH", filepath.Join(filepath.Dir(dataPath), ".offset"))

	// Pipeline 2: flat docs for Grafana
	flatIndex := getenv("ELASTICSEARCH_FLAT_INDEX", "audit-logs-flat")
	flatDataPath := getenv("ELASTICSEARCH_FLAT_DATA_PATH", "../shared/reports-flat.jsonl")
	flatOffsetPath := getenv("ELASTICSEARCH_FLAT_OFFSET_PATH", filepath.Join(filepath.Dir(flatDataPath), ".offset-flat"))

	log.Printf("sidecar tick | es=%s data=%s flat=%s flushEvery=%d auth=%t", elasticSearchURL, dataPath, flatDataPath, flushEvery, esUser != "" || esPass != "")

	if err := ensureIndex(ctx, client, elasticSearchURL, index, esUser, esPass); err != nil {
		return fmt.Errorf("ensure nested index: %w", err)
	}
	// ship nested
	if err := shipFileOnce(ctx, client, elasticSearchURL, index, dataPath, offsetPath, flushEvery, esUser, esPass); err != nil {
		return fmt.Errorf("nested pipeline error: %w", err)
	}

	if err := ensureIndex(ctx, client, elasticSearchURL, flatIndex, esUser, esPass); err != nil {
		return fmt.Errorf("ensure flat index: %w", err)
	}
	// ship flat
	if err := shipFileOnce(ctx, client, elasticSearchURL, flatIndex, flatDataPath, flatOffsetPath, flushEvery, esUser, esPass); err != nil {
		return fmt.Errorf("flat pipeline error: %w", err)
	}

	return nil
}

func readOffset(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, err
	}
	return v, nil
}

func writeOffset(path string, v int64) error {
	return os.WriteFile(path, []byte(strconv.FormatInt(v, 10)), 0644)
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
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

func getenvDuration(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if dur, err := time.ParseDuration(v); err == nil {
			return dur
		}
	}
	return d
}

func ensureIndex(ctx context.Context, client *http.Client, elasticSearchURL, index, esUser, esPass string) error {
	base := strings.TrimRight(elasticSearchURL, "/")

	// Check if index exists
	req, err := http.NewRequestWithContext(ctx, "HEAD", base+"/"+index, nil)
	if err != nil {
		return fmt.Errorf("create HEAD request: %w", err)
	}
	if esUser != "" || esPass != "" {
		req.SetBasicAuth(esUser, esPass)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HEAD index request failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode == 200 {
		return nil // exists
	}
	if resp.StatusCode != 404 {
		return fmt.Errorf("HEAD index unexpected status=%s", resp.Status)
	}

	// Create index
	createReq, err := http.NewRequestWithContext(ctx, "PUT", base+"/"+index, nil)
	if err != nil {
		return fmt.Errorf("create PUT request: %w", err)
	}
	if esUser != "" || esPass != "" {
		createReq.SetBasicAuth(esUser, esPass)
	}

	createResp, err := client.Do(createReq)
	if err != nil {
		return fmt.Errorf("PUT index request failed: %w", err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode < 200 || createResp.StatusCode > 299 {
		body, _ := io.ReadAll(createResp.Body)
		return fmt.Errorf("index create status=%s body=%s", createResp.Status, string(body))
	}

	log.Printf("created index %s", index)
	return nil
}
