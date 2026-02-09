package main

import (
	"encoding/base64"
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

type DecodedConfig struct { //in struct ham noke dare bnzrm ERROR
	ID      string
	Payload map[string]any
}

type SubjectKey struct {
	Kind string // "User" or "Group" (later could be "ServiceAccount")
	Name string
}

func LoadInputFile(path string) (*InputFile, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error while trying to read input.json: %w", err)
	}
	var in InputFile
	if err := json.Unmarshal(bytes, &in); err != nil {
		return nil, fmt.Errorf("error while trying to unmarshal input.json: %w", err)
	}
	return &in, nil
}

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

func SubjectsForPrincipal(p Principal) []SubjectKey {
	var subs []SubjectKey
	if p.Username != "" {
		subs = append(subs, SubjectKey{Kind: "User", Name: p.Username})
	}
	for _, g := range p.Groups {
		if g == "" {
			continue
		}
		subs = append(subs, SubjectKey{Kind: "Group", Name: g})
	}

	return subs
}

func DecodeBase64Data(in *InputFile) ([]DecodedConfig, error) {
	var out []DecodedConfig

	for _, entry := range in.Data {
		for _, c := range entry.Configs {
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.Data))
			if err != nil {
				return nil, fmt.Errorf("decode base64 config id=%s: %w", c.ID, err)
			}

			var payload map[string]any
			if err := json.Unmarshal(raw, &payload); err != nil {
				return nil, fmt.Errorf("decode config json id=%s: %w", c.ID, err)
			}

			out = append(out, DecodedConfig{ID: c.ID, Payload: payload})
		}
	}

	return out, nil
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
