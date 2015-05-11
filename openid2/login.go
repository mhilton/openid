package openid2

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var ErrUnauthenticated = errors.New("authentication failed")

// LoginRequest represents an openid login request.
type LoginRequest struct {
	ClaimedID  string
	Identity   string
	ReturnTo   string
	Realm      string
	Extensions []Extension
}

func parseLoginRequest(params map[string]string) (*LoginRequest, error) {
	extensions, err := parseExtensions(params)
	if err != nil {
		return nil, err
	}
	req := &LoginRequest{
		ClaimedID:  params["claimed_id"],
		Identity:   params["identity"],
		ReturnTo:   params["return_to"],
		Realm:      params["realm"],
		Extensions: extensions,
	}
	return req, nil
}

// LoginResponse represents the response to an openid login request.
type LoginResponse struct {
	ClaimedID  string
	Identity   string
	OPEndpoint string
	Extensions []Extension
}

// LoginHandler provides server-side handling of a LoginRequest.
type LoginHandler interface {
	Login(http.ResponseWriter, *http.Request, *LoginRequest) (*LoginResponse, error)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request, params map[string]string) {
	req, err := parseLoginRequest(params)
	if err != nil {
		indirect(w, params["return_to"]).respond(nil, err)
		return
	}
	var resp *LoginResponse
	switch params["mode"] {
	case "checkid_immediate":
		if h.Login != nil {
			resp, err = h.Login.Login(nil, r, req)
		}
		if err != nil && err != ErrUnauthenticated {
			indirect(w, params["return_to"]).respond(nil, err)
			return
		}
		if resp != nil {
			break
		}
		indirect(w, params["return_to"]).respond(map[string]string{
			"ns":   Namespace,
			"mode": "setup_needed",
		}, nil)
		return
	case "checkid_setup":
		if h.Login != nil {
			resp, err = h.Login.Login(w, r, req)
		}
		if err != nil && err != ErrUnauthenticated {
			indirect(w, params["return_to"]).respond(nil, err)
			return
		}
		if resp != nil {
			break
		}
		if err == nil {
			return
		}
		indirect(w, params["return_to"]).respond(map[string]string{
			"ns":   Namespace,
			"mode": "cancel",
		}, nil)
		return
	default:
		panic(fmt.Sprintf("login called with unexpected mode %q", params["mode"]))
	}
	if params["return_to"] == "" {
		direct(w).respond(nil, fmt.Errorf("cannot send id_res message, no return_to parameter"))
		return
	}
	nonce, err := h.getNonce()
	if err != nil {
		indirect(w, params["return_to"]).respond(nil, err)
		return
	}
	assoc, err := h.getAssociation(params["assoc_handle"], nonce)
	if err != nil {
		indirect(w, params["return_to"]).respond(nil, err)
		return
	}
	// encode the response
	signed := []string{
		"op_endpoint",
		"return_to",
		"response_nonce",
		"assoc_handle",
	}
	rparams := map[string]string{
		"ns":             Namespace,
		"mode":           "id_res",
		"return_to":      params["return_to"],
		"op_endpoint":    resp.OPEndpoint,
		"response_nonce": nonce,
		"assoc_handle":   assoc.Handle,
	}
	if resp.ClaimedID != "" {
		signed = append(signed, "claimed_id")
		rparams["claimed_id"] = resp.ClaimedID
	}
	if resp.Identity != "" {
		signed = append(signed, "identity")
		rparams["identity"] = resp.Identity
	}
	if params["assoc_handle"] != "" && params["assoc_handle"] != assoc.Handle {
		rparams["invalidate_handle"] = params["assoc_handle"]
	}
	signed = append(signed, encodeExtensions(rparams, resp.Extensions)...)
	rparams["signed"] = strings.Join(signed, ",")
	sig, err := assoc.sign(rparams, signed)
	if err != nil {
		indirect(w, params["return_to"]).respond(nil, err)
		return
	}
	rparams["sig"] = sig
	indirect(w, params["return_to"]).respond(rparams, nil)
}
