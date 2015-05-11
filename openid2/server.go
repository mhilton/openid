package openid2

import (
	"crypto/rand"
	"encoding/ascii85"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type Handler struct {
	Login        LoginHandler
	Associations AssociationStore
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	var params map[string]string
	switch r.Method {
	case "GET":
		params = ParseHTTP(r.URL.Query())
	case "POST":
		params = ParseHTTP(r.PostForm)
	}
	switch params["ns"] {
	case Namespace:
		break
	default:
		indirect(w, params["return_to"]).respond(nil, fmt.Errorf("unknown ns %q", params["ns"]))
	}
	switch params["mode"] {
	case "associate":
		direct(w).respond(h.associate(params))
	case "checkid_immediate", "checkid_setup":
		h.login(w, r, params)
	case "check_authentication":
		direct(w).respond(h.checkAuthentication(params))
	default:
		indirect(w, params["return_to"]).respond(nil, fmt.Errorf("unknown mode %q", params["mode"]))
	}
	return
}

func (h *Handler) getNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	enonce := make([]byte, ascii85.MaxEncodedLen(len(nonce)))
	n := ascii85.Encode(enonce, nonce[:])
	return fmt.Sprintf("%s%s", time.Now().UTC().Format(time.RFC3339), enonce[:n]), nil
}

type responder interface {
	respond(map[string]string, error)
}

func direct(w http.ResponseWriter) responder {
	return directResponder{w}
}

type directResponder struct {
	w http.ResponseWriter
}

func (d directResponder) respond(params map[string]string, err error) {
	if err != nil {
		d.w.WriteHeader(http.StatusBadRequest)
		params = makeError(err)
	}
	EncodeKeyValue(d.w, params)
}

func indirect(w http.ResponseWriter, returnTo string) responder {
	if returnTo == "" {
		return direct(w)
	}
	u, err := url.Parse(returnTo)
	if err != nil {
		return direct(w)
	}
	return &indirectResponder{w, u}
}

type indirectResponder struct {
	w        http.ResponseWriter
	returnTo *url.URL
}

func (i *indirectResponder) respond(params map[string]string, err error) {
	v := i.returnTo.Query()
	if err != nil {
		params = makeError(err)
	}
	EncodeHTTP(v, params)
	i.returnTo.RawQuery = v.Encode()
	i.w.Header().Set("Location", i.returnTo.String())
	i.w.WriteHeader(http.StatusSeeOther)
}

func makeError(err error) map[string]string {
	e := map[string]string{
		"ns":    Namespace,
		"mode":  "error",
		"error": err.Error(),
	}
	if err, ok := err.(errorParamser); ok {
		for k, v := range err.errorParams() {
			e[k] = v
		}
	}
	return e
}

type errorParamser interface {
	errorParams() map[string]string
}
