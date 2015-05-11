package openid2

import (
	"fmt"
	"strings"
)

type Extension struct {
	Namespace string
	Prefix    string
	Params    map[string]string
}

func parseExtensions(params map[string]string) ([]Extension, error) {
	prefixes := make(map[string]string)
	namespaces := make(map[string]string)
	for k, v := range params {
		parts := strings.SplitN(k, ".", 2)
		if len(parts) < 2 {
			continue
		}
		if parts[0] != "ns" {
			continue
		}
		prefix := parts[1]
		if bannedPrefixes[prefix] {
			return nil, fmt.Errorf("namespace prefix %q not allowed", prefix)
		}
		if ns, ok := prefixes[prefix]; ok && ns != v {
			return nil, fmt.Errorf("namespace prefix %q assigned to multiple namespaces", prefix)
		}
		ns := v
		if p, ok := namespaces[ns]; ok && p != prefix {
			return nil, fmt.Errorf("namespace %q assigned to multiple prefixes", ns)
		}
		namespaces[ns] = prefix
		prefixes[prefix] = ns
	}
	extensions := make([]Extension, len(prefixes))
	positions := make(map[string]int)
	i := 0
	for p, ns := range prefixes {
		extensions[i] = Extension{
			Namespace: ns,
			Prefix:    p,
			Params:    map[string]string{},
		}
		positions[p] = i
		i++
	}
	for k, v := range params {
		parts := strings.SplitN(k, ".", 2)
		if len(parts) < 2 {
			continue
		}
		if parts[0] == "ns" {
			continue
		}
		prefix := parts[0]
		key := parts[1]
		pos, ok := positions[prefix]
		if !ok {
			continue
		}
		extensions[pos].Params[key] = v
	}
	return extensions, nil
}

func encodeExtensions(params map[string]string, extensions []Extension) (signed []string) {
	var i int
	used := map[string]bool{}
	for _, ext := range extensions {
		prefix := ext.Prefix
		for bannedPrefixes[prefix] || used[prefix] {
			prefix = fmt.Sprintf("ext%d", i)
			i++
		}
		used[prefix] = true
		params["ns."+prefix] = ext.Namespace
		for k, v := range ext.Params {
			key := fmt.Sprintf("%s.%s", prefix, k)
			params[key] = v
			signed = append(signed, key)
		}
	}
	return
}

var bannedPrefixes = map[string]bool{
	"assoc_handle":       true,
	"assoc_type":         true,
	"claimed_id":         true,
	"contact":            true,
	"delegate":           true,
	"dh_consumer_public": true,
	"dh_gen":             true,
	"dh_modulus":         true,
	"error":              true,
	"identity":           true,
	"invalidate_handle":  true,
	"mode":               true,
	"ns":                 true,
	"op_endpoint":        true,
	"openid":             true,
	"realm":              true,
	"reference":          true,
	"response_nonce":     true,
	"return_to":          true,
	"server":             true,
	"session_type":       true,
	"sig":                true,
	"signed":             true,
	"trust_root":         true,
}
