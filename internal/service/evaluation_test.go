package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// measuredFixture fixes observation timestamps only in synthetic evaluation
// artifacts, so byte counts are repeatable while production retains real time.
func measuredFixture(t *testing.T, name string, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	var normalize func(any) any
	normalize = func(value any) any {
		switch v := value.(type) {
		case map[string]any:
			for k, child := range v {
				v[k] = normalize(child)
			}
		case []any:
			for i, child := range v {
				v[i] = normalize(child)
			}
		case string:
			if _, err := time.Parse(time.RFC3339Nano, v); err == nil {
				return "2026-11-07T00:00:00Z"
			}
		}
		return value
	}
	encoded, err = json.Marshal(normalize(decoded))
	if err != nil {
		t.Fatal(err)
	}
	if dir := os.Getenv("FORTI_EVAL_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), encoded, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return encoded
}
