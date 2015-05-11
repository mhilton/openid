package openid2

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/ascii85"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

const (
	hmacSHA1   = "HMAC-SHA1"
	hmacSHA256 = "HMAC-SHA256"
)

var ErrDuplicateAssociation = errors.New("duplicate association")

// Association represents an openid association.
type Association struct {
	// Endpoint is the OP Endpoint for which this association is valid. It might be blank.
	Endpoint string

	// Handle is used to identify the association with the OP Endpoint.
	Handle string

	// Secret is the secret established with the OP Endpoint.
	Secret []byte

	// Type is the type of this association.
	Type string

	// Expires holds the expiration time of the association.
	Expires time.Time
}

func (a Association) sign(params map[string]string, signed []string) (string, error) {
	var h hash.Hash
	switch a.Type {
	case hmacSHA1:
		h = hmac.New(sha1.New, a.Secret)
	case hmacSHA256:
		h = hmac.New(sha256.New, a.Secret)
	default:
		return "", fmt.Errorf("unsupported association type %q", a.Type)
	}
	for _, k := range signed {
		WriteKeyValuePair(h, k, params[k])
	}
	return base64.URLEncoding.EncodeToString(h.Sum(nil)), nil
}

// AssociationStore is used to store associations in both the server and client.
type AssociationStore interface {
	// Add stores a new Association. If the specified Association is already
	// present in the store then ErrDuplicateAssociation should be returned.
	Add(a *Association) error

	// Get retrieves the Association with the specified endpoint and handle.
	// if there is no matching association in the store then ErrAssociationNotFound
	// should be returned.
	Get(endpoint, handle string) (*Association, error)

	// Find retrieves all Associations for the specified endpoint.
	Find(endpoint string) ([]*Association, error)

	// Delete removes the Association with the specified endpoint and handle.
	Delete(endpoint, handle string) error
}

// MemoryAssociationStore is an in memory implementation of AssociationStore.
type MemoryAssociationStore struct {
	m map[string]map[string]Association
}

// NewMemoryAssociationStore creates a new in memory AssocationStore.
func NewMemoryAssociationStore() *MemoryAssociationStore {
	return &MemoryAssociationStore{map[string]map[string]Association{}}
}

// Add implements AssociationStore.Add.
func (s *MemoryAssociationStore) Add(a *Association) error {
	ass, err := s.Get(a.Endpoint, a.Handle)
	if err != nil {
		return err
	}
	if ass != nil {
		return ErrDuplicateAssociation
	}
	m := s.m[a.Endpoint]
	if m == nil {
		m = make(map[string]Association)
	}
	m[a.Handle] = *a
	s.m[a.Endpoint] = m
	return nil
}

// Find implements AssociationStore.Find.
func (s *MemoryAssociationStore) Find(endpoint string) ([]*Association, error) {
	var assocs []*Association
	for _, a := range s.m[endpoint] {
		assocs = append(assocs, &a)
	}
	return assocs, nil
}

// Get implements AssociationStore.Get.
func (s *MemoryAssociationStore) Get(endpoint, handle string) (*Association, error) {
	if s.m[endpoint] == nil {
		return nil, nil
	}
	a, ok := s.m[endpoint][handle]
	if !ok {
		return nil, nil
	}
	return &a, nil
}

// Delete implements AssociationStore.Delete.
func (s *MemoryAssociationStore) Delete(endpoint, handle string) error {
	a, err := s.Get(endpoint, handle)
	if err != nil {
		return err
	}
	if a == nil {
		return nil
	}
	delete(s.m[endpoint], handle)
	return nil
}

// DefaultAssociationStore is the AssociationStore that will be used if no AssociationStore
// is specified.
var DefaultAssociationStore AssociationStore = NewMemoryAssociationStore()

func (h *Handler) getAssociation(requestHandle, nonce string) (a *Association, err error) {
	store := h.Associations
	if store == nil {
		store = DefaultAssociationStore
	}
	if requestHandle != "" {
		a, err = store.Get("", requestHandle)
		if err != nil {
			return
		}
		if a != nil {
			if time.Now().Before(a.Expires) {
				return
			}
			store.Delete("", requestHandle)
		}
	}
	secret := make([]byte, 128)
	if _, err = rand.Read(secret); err != nil {
		return
	}
	a = &Association{
		Secret:  secret,
		Type:    hmacSHA256,
		Expires: time.Now().Add(time.Minute),
	}
	err = saveAssociation(store, a)
	if err != nil {
		a = nil
	}
	return
}

func (h *Handler) associate(params map[string]string) (map[string]string, error) {
	//	store := h.Associations
	//	if store == nil {
	//		assocs = DefaultAssociationStore
	//	}

	switch params["session_type"] {
	//	case "DH-SHA1":
	//	case "DH-SHA256":
	//	case "no-encryption":
	//		return h.associateNoEncryption(params)
	default:
		return nil, unsupportedSessionTypeError(params["session_type"])
	}
}

func (h *Handler) checkAuthentication(params map[string]string) (map[string]string, error) {
	store := h.Associations
	if store == nil {
		store = DefaultAssociationStore
	}
	assoc, err := store.Get("", params["assoc_handle"])
	if err != nil {
		return nil, err
	}
	if assoc == nil {
		return map[string]string{
			"ns":       Namespace,
			"is_valid": "false",
		}, nil
	}
	signed := strings.Split(params["signed"], ",")
	sig, err := assoc.sign(params, signed)
	if err != nil {
		return nil, err
	}
	if params["sig"] != sig {
		return map[string]string{
			"ns":       Namespace,
			"is_valid": "false",
		}, nil
	}
	rparams := map[string]string{
		"ns":       Namespace,
		"is_valid": "true",
	}
	// TODO: deal with invalid_handle
	store.Delete("", assoc.Handle)
	return rparams, nil
}

func saveAssociation(store AssociationStore, a *Association) error {
	for i := 0; i < 10; i++ {
		var handle [16]byte
		if _, err := rand.Read(handle[:]); err != nil {
			return err
		}
		ehandle := make([]byte, ascii85.MaxEncodedLen(len(handle)))
		n := ascii85.Encode(ehandle, handle[:])
		a.Handle = string(ehandle[:n])
		err := store.Add(a)
		if err == nil {
			return nil
		}
		if err != ErrDuplicateAssociation {
			return err
		}
	}
	return errors.New("cannot store association")
}

type unsupportedSessionTypeError string

func (e unsupportedSessionTypeError) Error() string {
	return fmt.Sprintf("session type %q not supported", string(e))
}

func (e unsupportedSessionTypeError) errorParams() map[string]string {
	return map[string]string{
		"error-code": "unsupported-type",
	}
}
