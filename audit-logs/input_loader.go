package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/json"
)

type InputFile struct {
	Metadata struct {
		Timestamp time.Time `json:"timestamp"`
		Version   string    `json:"version"`
	} `json:"metadata"`
	Data []InputDataEntry `json:"data"`
}

type InputDataEntry struct {
	Configs   []InputConfig        `json:"configs"`
	Internals map[string]Principal `json:"internals"` // key = internal id
}

type InputConfig struct {
	ID   string `json:"id"`
	Data string `json:"data"` // base64-encoded JSON
}

type Principal struct {
	InternalID string   `json:"-"`
	Source     string   `json:"source"`
	Username   string   `json:"username"`
	Groups     []string `json:"groups"`
	FirstName  string   `json:"first_name"`
	LastName   string   `json:"last_name"`
}

func LoadInputFile(path string) (*InputFile, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error while trying to read input file %s: %w", path, err)
	}
	var in InputFile
	if err := json.Unmarshal(bytes, &in); err != nil {
		return nil, fmt.Errorf("error while trying to unmarshal input file %s: %w", path, err)
	}
	return &in, nil
}

// ExtractPrincipals extract the user details from the input.json
func ExtractPrincipals(in *InputFile) []Principal {
	var out []Principal

	for _, entry := range in.Data {
		for internalID, v := range entry.Internals {
			p := Principal{
				InternalID: internalID,
				Source:     v.Source,
				Username:   v.Username,
				Groups:     normalizeAndSortGroups(v.Groups),
				FirstName:  v.FirstName,
				LastName:   v.LastName,
			}
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Username < out[j].Username
	})
	return out
}

func normalizeAndSortGroups(groups []string) []string {
	seen := make(map[string]struct{}, len(groups))
	var out []string

	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}

	sort.Strings(out)
	return out
}
