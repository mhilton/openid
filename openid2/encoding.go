package openid2

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const Namespace = "http://specs.openid.net/auth/2.0"

// ParseHTTP parses openid values from the parameters in a url.Values.
func ParseHTTP(v url.Values) map[string]string {
	p := make(map[string]string)
	for k, v := range v {
		if strings.HasPrefix(k, "openid.") && len(v) > 0 {
			p[strings.TrimPrefix(k, "openid.")] = v[0]
		}
	}
	return p
}

// EncodeHTTP updates v with the encoding of p.
func EncodeHTTP(v url.Values, p map[string]string) {
	for k, pv := range p {
		v.Set("openid."+k, pv)
	}
}

// ParseKeyValue
func ParseKeyValue(body []byte) (map[string]string, error) {
	p := make(map[string]string)
	for _, b := range bytes.Split(body, []byte("\n")) {
		parts := bytes.SplitN(b, []byte(":"), 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key-value line %q", b)
		}
		p[string(parts[0])] = string(parts[1])
	}
	return p, nil
}

func EncodeKeyValue(w io.Writer, p map[string]string) error {
	for k, v := range p {
		if err := WriteKeyValuePair(w, k, v); err != nil {
			return err
		}
	}
	return nil
}

func WriteKeyValuePair(w io.Writer, key, value string) error {
	_, err := fmt.Fprintf(w, "%s:%s\n", key, value)
	return err
}
