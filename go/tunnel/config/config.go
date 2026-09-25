// Package config loads the agent and server YAML files and the agent's
// command line into the relay and agent configurations.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"go.yaml.in/yaml/v3"
)

// TokenEnv is the environment variable holding the agent token when none
// is given on the command line or in the config file.
const TokenEnv = "L8TUNNEL_TOKEN"

// envRef matches a value that is exactly ${NAME}.
var envRef = regexp.MustCompile(`^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$`)

// decodeStrict decodes a YAML file into out, rejecting unknown keys so a
// typo or an option this version doesn't support fails loudly.
func decodeStrict(path string, out interface{}) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("config %s is empty", path)
		}
		return fmt.Errorf("config %s: %w", path, err)
	}
	return nil
}

// expandEnv resolves a value written as ${NAME} from the environment. Other
// values are returned unchanged, so strings containing '$' (such as
// password hashes) are never mangled. A reference to an unset variable is
// an error.
func expandEnv(field, value string) (string, error) {
	m := envRef.FindStringSubmatch(value)
	if m == nil {
		return value, nil
	}
	v, ok := os.LookupEnv(m[1])
	if !ok {
		return "", fmt.Errorf("%s refers to ${%s}, which is not set", field, m[1])
	}
	return v, nil
}
