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

func shipOnce(ctx context.Context, client *http.Client) error {
	elasticSearchURL := getenv("ELASTICSEARCH_URL", "https://mahdixak-security-auditdb.darkube.app/")
	index := getenv("ELASTICSEARCH_INDEX", "audit-logs")
	dataPath := getenv("ELASTICSEARCH_DATA_PATH", "../shared/reports.jsonl")
	offsetPath := getenv("ELASTICSEARCH_OFFSET_PATH", "../shared/.offset")
	flushEvery := getenvInt("FLUSH_EVERY", 10) // batch size
	esUser := os.Getenv("ES_USERNAME")
	esPass := os.Getenv("ES_PASSWORD")

	log.Printf("sidecar starting | es=%s index=%s dataPath=%s offsetPath=%s flushEvery=%d user=%s basicAuth=%t",
		elasticSearchURL, index, dataPath, offsetPath, flushEvery, esUser, esPass != "")

	//off, _ := readOffset(offsetPath)
	f, err := os.Open(dataPath)
	//if err != nil && !os.IsNotExist(err) {
	//	log.Printf("readOffset warning (will start from 0): %v", err)
	//	off = 0
	//}
	off, offErr := readOffset(offsetPath)
	if offErr != nil && !os.IsNotExist(offErr) {
		log.Printf("readOffset warning (starting from 0): %v", offErr)
		off = 0
	}

	if err != nil {
		if os.IsNotExist(err) { // if the file is not created yet we will wait
			log.Printf("data file not found yet (%s) - waiting...", dataPath)
			log.Printf("error is : %v", err)
			time.Sleep(10 * time.Second)
			return nil
		}
		return fmt.Errorf("open data file: %w", err)
	}
	defer f.Close()

	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return fmt.Errorf("seek to offset %d: %w", off, err)
	}

	log.Printf("shipping started | dataPath=%s fromOffset=%d", dataPath, off)

	r := bufio.NewReader(f)

	var (
		bulk bytes.Buffer
		n    int
	)
	flush := func(newOffset int64) error {
		if n == 0 {
			return nil
		}

		req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(elasticSearchURL, "/")+"/_bulk", bytes.NewReader(bulk.Bytes()))
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

		// IMPORTANT: detect partial failures
		var br BulkResp
		if err := json.Unmarshal(body, &br); err != nil {
			// if ES returns something unexpected, be safe: don't advance offset
			return fmt.Errorf("bulk response decode error: %w body=%s", err, string(body))
		}
		if br.Errors {
			// log a few errors; do NOT advance offset
			log.Printf("bulk partial errors detected; NOT advancing offset")
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

		log.Printf("flush success | docs=%d wroteOffset=%d", n, newOffset)
		bulk.Reset()
		n = 0
		return nil
	}

	for {
		startOffset, _ := f.Seek(0, io.SeekCurrent)
		line, err := r.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				// If we got partial data without newline, ship it too
				if len(bytes.TrimSpace(line)) > 0 {
					// process 'line' exactly like a normal line
					line = bytes.TrimSpace(line)

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
			continue // skip empty lines safely
		}

		// optional: validate JSON line (cheap safety)
		var js any
		if err := json.Unmarshal(line, &js); err != nil {
			return fmt.Errorf("invalid json at offset %d: %w | line=%s", startOffset, err, string(line))
		}

		// Add stable _id to prevent duplicates on retry/restart
		docID := stableID(line)

		action := BulkAction{Index: map[string]string{
			"_index": index,
			"_id":    docID,
		}}

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
