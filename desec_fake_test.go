package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nrdcg/desec"
)

// fakeDesec is a minimal in-memory implementation of the parts of the deSEC
// API (https://desec.readthedocs.io/en/latest/) used by the solver.
type fakeDesec struct {
	t     *testing.T
	token string

	mu      sync.Mutex
	domains []desec.Domain
	rrsets  map[string]desec.RRSet // key: domain/subname/type
	calls   []string               // "METHOD path"

	// failOn makes requests whose "METHOD path" starts with the given prefix
	// fail with the given status code.
	failOn     string
	failStatus int
}

func newFakeDesec(t *testing.T, token string, domains ...desec.Domain) (*fakeDesec, *httptest.Server) {
	t.Helper()

	f := &fakeDesec{t: t, token: token, domains: domains, rrsets: map[string]desec.RRSet{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(srv.Close)

	return f, srv
}

// client returns a deSEC client pointed at the fake server, without retries.
func (f *fakeDesec) clientFactory(srv *httptest.Server) func(string) *desec.Client {
	return func(token string) *desec.Client {
		opts := desec.NewDefaultClientOptions()
		opts.RetryMax = 0
		c := desec.New(token, opts)
		c.BaseURL = srv.URL + "/api/v1/"

		return c
	}
}

func rrKey(domain, subName, typ string) string {
	if subName == "" || subName == desec.ApexZone {
		subName = ""
	}

	return domain + "/" + subName + "/" + typ
}

func (f *fakeDesec) put(rr desec.RRSet) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.rrsets[rrKey(rr.Domain, rr.SubName, rr.Type)] = rr
}

func (f *fakeDesec) get(domain, subName, typ string) (desec.RRSet, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	rr, ok := f.rrsets[rrKey(domain, subName, typ)]

	return rr, ok
}

func (f *fakeDesec) callCount(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	n := 0

	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}

	return n
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Not found."})
}

func (f *fakeDesec) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	call := r.Method + " " + r.URL.Path
	f.calls = append(f.calls, call)

	if r.Header.Get("Authorization") != "Token "+f.token {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "Invalid token."})
		return
	}

	if f.failOn != "" && strings.HasPrefix(call, f.failOn) {
		writeJSON(w, f.failStatus, map[string]string{"detail": "injected failure"})
		return
	}

	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/"), "/")

	switch {
	// GET /domains/?owns_qname=<name>
	case len(parts) == 1 && parts[0] == "domains" && r.Method == http.MethodGet:
		f.listDomains(w, r)

	// POST /domains/<domain>/rrsets/
	case len(parts) == 3 && parts[0] == "domains" && parts[2] == "rrsets" && r.Method == http.MethodPost:
		f.createRRSet(w, r, parts[1])

	// GET|PATCH|DELETE /domains/<domain>/rrsets/<subname>/<type>/
	case len(parts) == 5 && parts[0] == "domains" && parts[2] == "rrsets":
		f.handleRRSet(w, r, parts[1], parts[3], parts[4])

	default:
		f.t.Errorf("fake deSEC: unexpected request %s", call)
		notFound(w)
	}
}

func (f *fakeDesec) listDomains(w http.ResponseWriter, r *http.Request) {
	qname := r.URL.Query().Get("owns_qname")
	if qname == "" {
		writeJSON(w, http.StatusOK, f.domains)
		return
	}

	// deSEC returns the single most specific domain owning the name.
	var best *desec.Domain

	for i, d := range f.domains {
		if (qname == d.Name || strings.HasSuffix(qname, "."+d.Name)) && (best == nil || len(d.Name) > len(best.Name)) {
			best = &f.domains[i]
		}
	}

	if best == nil {
		writeJSON(w, http.StatusOK, []desec.Domain{})
		return
	}

	writeJSON(w, http.StatusOK, []desec.Domain{*best})
}

func (f *fakeDesec) hasDomain(name string) bool {
	return slices.ContainsFunc(f.domains, func(d desec.Domain) bool { return d.Name == name })
}

func (f *fakeDesec) createRRSet(w http.ResponseWriter, r *http.Request, domain string) {
	if !f.hasDomain(domain) {
		notFound(w)
		return
	}

	var rr desec.RRSet
	if err := json.NewDecoder(r.Body).Decode(&rr); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
		return
	}

	key := rrKey(domain, rr.SubName, rr.Type)
	if _, exists := f.rrsets[key]; exists {
		writeJSON(w, http.StatusBadRequest, map[string][]string{"non_field_errors": {"Another RRset with the same subdomain and type exists for this domain."}})
		return
	}

	rr.Domain = domain
	f.rrsets[key] = rr
	writeJSON(w, http.StatusCreated, rr)
}

func (f *fakeDesec) handleRRSet(w http.ResponseWriter, r *http.Request, domain, subName, typ string) {
	key := rrKey(domain, subName, typ)
	rr, exists := f.rrsets[key]

	switch r.Method {
	case http.MethodGet:
		if !exists {
			notFound(w)
			return
		}

		writeJSON(w, http.StatusOK, rr)

	case http.MethodPatch:
		if !exists {
			notFound(w)
			return
		}

		var patch desec.RRSet
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
			return
		}

		if len(patch.Records) == 0 {
			delete(f.rrsets, key)
			w.WriteHeader(http.StatusNoContent)

			return
		}

		rr.Records = patch.Records
		f.rrsets[key] = rr
		writeJSON(w, http.StatusOK, rr)

	case http.MethodDelete:
		// deSEC answers 204 even if the RRset does not exist.
		delete(f.rrsets, key)
		w.WriteHeader(http.StatusNoContent)

	default:
		f.t.Errorf("fake deSEC: unexpected method %s on %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
