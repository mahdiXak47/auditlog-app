package main

import (
	"bufio"
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
)

type Bulkline struct {
	Index map[string]string `json:"index"`
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
	index := getenv("ELASTICSEARCH_INDEX", "rbac-audit")
	dataPath := getenv("ELASTICSEARCH_DATA_PATH", "../shared/reports.jsonl")
	offsetPath := getenv("ELASTICSEARCH_OFFSET_PATH", "../shared/.offset")
	flushEvery := getenvInt("FLUSH_EVERY", 200) // batch size
	off, _ := readOffset(offsetPath)
	esUser := os.Getenv("ES_USERNAME")
	esPass := os.Getenv("ES_PASSWORD")
	f, err := os.Open(dataPath)

	//log.Printf("sidecar starting | es=%s index=%s dataPath=%s offsetPath=%s flushEvery=%d pollEvery=%s basicAuth=%t",
	//	elasticSearchURL, index, dataPath, offsetPath, flushEvery, esUser != "" || esPass != "")

	if err != nil && !os.IsNotExist(err) {
		log.Printf("readOffset warning (will start from 0): %v", err)
		off = 0
	}

	if err != nil {
		if os.IsNotExist(err) { // if the file is not created yet we will wait
			log.Printf("data file not found yet (%s) - waiting...", dataPath)
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

		req, err := http.NewRequestWithContext(ctx, "POST", elasticSearchURL+"/_bulk", bytes.NewReader(bulk.Bytes()))
		if err != nil {
			return fmt.Errorf("create bulk request: %w", err)
		}

		req.Header.Set("Content-Type", "application/x-ndjson")

		if esUser != "" || esPass != "" {
			req.SetBasicAuth(esUser, esPass)
		}

		log.Printf("flushing | docs=%d bytes=%d newOffset=%d", n, bulk.Len(), newOffset)

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("bulk request failed: %w", err)
		}

		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("bulk status=%s body=%s", resp.Status, string(body))
		}

		if err := writeOffset(offsetPath, newOffset); err != nil {
			return err
		}

		log.Printf("flush success | docs=%d wroteOffset=%d", n, newOffset)

		bulk.Reset()
		n = 0
		return nil
	}

	for {
		startOffset, _ := f.Seek(0, io.SeekCurrent)

		//line, err := r.ReadString('\n')
		line, err := r.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				endOffset, _ := f.Seek(0, io.SeekCurrent)
				return flush(endOffset)
			}
			return fmt.Errorf("read bytes: %w", err)
		}

		if len(bytes.TrimSpace(line)) == 0 {
			return fmt.Errorf("invalid json in offset %d: %s", startOffset, line)
		}

		action := Bulkline{Index: map[string]string{"_index": index}}
		ab, _ := json.Marshal(action)
		bulk.Write(ab)
		bulk.WriteByte('\n')
		bulk.Write(bytes.TrimSpace(line))
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
