package main

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/nrdcg/desec"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	testToken     = "test-token"
	testNamespace = "cert-manager"
)

type testEnv struct {
	solver *desecDNSProviderSolver
	desec  *fakeDesec
}

func newTestEnv(t *testing.T, domains ...desec.Domain) *testEnv {
	t.Helper()

	if len(domains) == 0 {
		domains = []desec.Domain{{Name: "example.com", MinimumTTL: 3600}}
	}

	f, srv := newFakeDesec(t, testToken, domains...)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "desec-token", Namespace: testNamespace},
		Data:       map[string][]byte{"token": []byte(testToken + "\n")},
	}

	return &testEnv{
		solver: &desecDNSProviderSolver{
			client:         fake.NewClientset(secret),
			newDesecClient: f.clientFactory(srv),
		},
		desec: f,
	}
}

func challenge(fqdn, key string) *v1alpha1.ChallengeRequest {
	return &v1alpha1.ChallengeRequest{
		ResolvedFQDN:      fqdn,
		ResolvedZone:      "example.com.",
		Key:               key,
		ResourceNamespace: testNamespace,
		Config:            &extapi.JSON{Raw: []byte(`{"apiKeySecretRef":{"name":"desec-token","key":"token"}}`)},
	}
}

func TestName(t *testing.T) {
	if got := newSolver().Name(); got != "desec" {
		t.Fatalf("Name() = %q, want %q", got, "desec")
	}
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *extapi.JSON
		wantErr string
	}{
		{name: "missing config", cfg: nil, wantErr: "solver config is missing"},
		{name: "invalid json", cfg: &extapi.JSON{Raw: []byte(`{`)}, wantErr: "decoding solver config"},
		{name: "missing secret name", cfg: &extapi.JSON{Raw: []byte(`{"apiKeySecretRef":{"key":"token"}}`)}, wantErr: "apiKeySecretRef.name"},
		{name: "missing secret key", cfg: &extapi.JSON{Raw: []byte(`{"apiKeySecretRef":{"name":"s"}}`)}, wantErr: "apiKeySecretRef.key"},
		{name: "valid", cfg: &extapi.JSON{Raw: []byte(`{"apiKeySecretRef":{"name":"s","key":"k"}}`)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadConfig(tt.cfg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("loadConfig() error = %v, want error containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("loadConfig() unexpected error: %v", err)
			}

			want := cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: "s"}, Key: "k"}
			if cfg.APIKeySecretRef != want {
				t.Fatalf("loadConfig() = %+v, want %+v", cfg.APIKeySecretRef, want)
			}
		})
	}
}

func TestSubNameFor(t *testing.T) {
	tests := []struct {
		name, zone string
		want       string
		wantErr    bool
	}{
		{name: "_acme-challenge.example.com", zone: "example.com", want: "_acme-challenge"},
		{name: "_acme-challenge.example.com.", zone: "example.com.", want: "_acme-challenge"},
		{name: "_acme-challenge.www.example.com", zone: "example.com", want: "_acme-challenge.www"},
		{name: "_ACME-Challenge.Example.COM", zone: "example.com", want: "_acme-challenge"},
		{name: "example.com", zone: "example.com", want: ""},
		{name: "_acme-challenge.notexample.com", zone: "example.com", wantErr: true},
		{name: "_acme-challenge.example.org", zone: "example.com", wantErr: true},
		{name: ".example.com", zone: "example.com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name+"@"+tt.zone, func(t *testing.T) {
			got, err := subNameFor(tt.name, tt.zone)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("subNameFor() = %q, want error", got)
				}

				return
			}

			if err != nil || got != tt.want {
				t.Fatalf("subNameFor() = %q, %v, want %q", got, err, tt.want)
			}
		})
	}
}

func TestGetSecretKey(t *testing.T) {
	secrets := []*corev1.Secret{
		{ObjectMeta: metav1.ObjectMeta{Name: "tok", Namespace: "a"}, Data: map[string][]byte{"token": []byte("  abc\n"), "empty": []byte(" \n")}},
		{ObjectMeta: metav1.ObjectMeta{Name: "tok", Namespace: "b"}, Data: map[string][]byte{"token": []byte("xyz")}},
	}
	s := &desecDNSProviderSolver{client: fake.NewClientset(secrets[0], secrets[1])}

	ref := func(name, key string) cmmeta.SecretKeySelector {
		return cmmeta.SecretKeySelector{LocalObjectReference: cmmeta.LocalObjectReference{Name: name}, Key: key}
	}

	tests := []struct {
		name      string
		ref       cmmeta.SecretKeySelector
		namespace string
		want      string
		wantErr   string
	}{
		{name: "trims whitespace", ref: ref("tok", "token"), namespace: "a", want: "abc"},
		{name: "uses resource namespace", ref: ref("tok", "token"), namespace: "b", want: "xyz"},
		{name: "secret missing", ref: ref("nope", "token"), namespace: "a", wantErr: "getting secret a/nope"},
		{name: "secret in other namespace", ref: ref("tok", "token"), namespace: "c", wantErr: "getting secret c/tok"},
		{name: "key missing", ref: ref("tok", "other"), namespace: "a", wantErr: `key "other" not found`},
		{name: "empty value", ref: ref("tok", "empty"), namespace: "a", wantErr: "is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.getSecretKey(t.Context(), tt.ref, tt.namespace)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("getSecretKey() = %q, %v, want error containing %q", got, err, tt.wantErr)
				}

				return
			}

			if err != nil || got != tt.want {
				t.Fatalf("getSecretKey() = %q, %v, want %q", got, err, tt.want)
			}
		})
	}
}

func TestPresentCreatesRecord(t *testing.T) {
	env := newTestEnv(t, desec.Domain{Name: "example.com", MinimumTTL: 3600})

	if err := env.solver.Present(challenge("_acme-challenge.example.com.", "key1")); err != nil {
		t.Fatalf("Present() error: %v", err)
	}

	rr, ok := env.desec.get("example.com", "_acme-challenge", "TXT")
	if !ok {
		t.Fatal("TXT RRset was not created")
	}

	if !slices.Equal(rr.Records, []string{`"key1"`}) {
		t.Errorf("records = %v, want [\"key1\"]", rr.Records)
	}

	if rr.TTL != 3600 {
		t.Errorf("TTL = %d, want 3600", rr.TTL)
	}
}

func TestPresentUsesDomainMinimumTTL(t *testing.T) {
	tests := []struct {
		minTTL, want int
	}{
		{minTTL: 60, want: 60},
		{minTTL: 0, want: defaultTTL},
	}

	for _, tt := range tests {
		env := newTestEnv(t, desec.Domain{Name: "example.com", MinimumTTL: tt.minTTL})

		if err := env.solver.Present(challenge("_acme-challenge.example.com.", "key1")); err != nil {
			t.Fatalf("Present() error: %v", err)
		}

		rr, _ := env.desec.get("example.com", "_acme-challenge", "TXT")
		if rr.TTL != tt.want {
			t.Errorf("minimum_ttl %d: TTL = %d, want %d", tt.minTTL, rr.TTL, tt.want)
		}
	}
}

func TestPresentAppendsToExistingRecord(t *testing.T) {
	env := newTestEnv(t)
	env.desec.put(desec.RRSet{Domain: "example.com", SubName: "_acme-challenge", Type: "TXT", Records: []string{`"other"`}, TTL: 3600})

	if err := env.solver.Present(challenge("_acme-challenge.example.com.", "key1")); err != nil {
		t.Fatalf("Present() error: %v", err)
	}

	rr, _ := env.desec.get("example.com", "_acme-challenge", "TXT")
	if !slices.Equal(rr.Records, []string{`"other"`, `"key1"`}) {
		t.Errorf("records = %v, want [\"other\" \"key1\"]", rr.Records)
	}
}

func TestPresentIsIdempotent(t *testing.T) {
	env := newTestEnv(t)
	ch := challenge("_acme-challenge.example.com.", "key1")

	for range 3 {
		if err := env.solver.Present(ch); err != nil {
			t.Fatalf("Present() error: %v", err)
		}
	}

	rr, _ := env.desec.get("example.com", "_acme-challenge", "TXT")
	if !slices.Equal(rr.Records, []string{`"key1"`}) {
		t.Errorf("records = %v, want [\"key1\"]", rr.Records)
	}

	if n := env.desec.callCount("PATCH"); n != 0 {
		t.Errorf("got %d PATCH requests, want 0", n)
	}
}

func TestPresentPicksMostSpecificDomain(t *testing.T) {
	env := newTestEnv(t,
		desec.Domain{Name: "example.com"},
		desec.Domain{Name: "sub.example.com"},
		desec.Domain{Name: "notexample.com"},
	)

	if err := env.solver.Present(challenge("_acme-challenge.www.sub.example.com.", "key1")); err != nil {
		t.Fatalf("Present() error: %v", err)
	}

	if _, ok := env.desec.get("sub.example.com", "_acme-challenge.www", "TXT"); !ok {
		t.Error("record was not created in the most specific domain sub.example.com")
	}

	if _, ok := env.desec.get("example.com", "_acme-challenge.www.sub", "TXT"); ok {
		t.Error("record was created in the parent domain example.com")
	}
}

func TestPresentUnknownDomain(t *testing.T) {
	env := newTestEnv(t, desec.Domain{Name: "example.com"})

	err := env.solver.Present(challenge("_acme-challenge.notexample.com.", "key1"))
	if err == nil || !strings.Contains(err.Error(), "no deSEC domain") {
		t.Fatalf("Present() error = %v, want 'no deSEC domain' error", err)
	}

	if n := env.desec.callCount("POST"); n != 0 {
		t.Errorf("got %d POST requests, want 0", n)
	}
}

func TestPresentReturnsAPIErrors(t *testing.T) {
	tests := []struct {
		name   string
		failOn string
	}{
		{name: "domain lookup", failOn: "GET /api/v1/domains/"},
		{name: "rrset lookup", failOn: "GET /api/v1/domains/example.com/rrsets/"},
		{name: "create", failOn: "POST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.desec.failOn = tt.failOn
			env.desec.failStatus = http.StatusInternalServerError

			if err := env.solver.Present(challenge("_acme-challenge.example.com.", "key1")); err == nil {
				t.Fatal("Present() returned nil, want error")
			}
		})
	}
}

func TestPresentUpdateError(t *testing.T) {
	env := newTestEnv(t)
	env.desec.put(desec.RRSet{Domain: "example.com", SubName: "_acme-challenge", Type: "TXT", Records: []string{`"other"`}})
	env.desec.failOn = "PATCH"
	env.desec.failStatus = http.StatusBadRequest

	if err := env.solver.Present(challenge("_acme-challenge.example.com.", "key1")); err == nil {
		t.Fatal("Present() returned nil, want error")
	}
}

func TestPresentUsesTokenFromSecret(t *testing.T) {
	env := newTestEnv(t)

	// The fake API rejects every token except testToken, so a wrong token
	// must surface as an error.
	env.desec.token = "another-token"

	if err := env.solver.Present(challenge("_acme-challenge.example.com.", "key1")); err == nil {
		t.Fatal("Present() returned nil with a token the API rejects, want error")
	}
}

func TestPresentWithoutConfigMakesNoAPICalls(t *testing.T) {
	env := newTestEnv(t)
	ch := challenge("_acme-challenge.example.com.", "key1")
	ch.Config = nil

	if err := env.solver.Present(ch); err == nil {
		t.Fatal("Present() returned nil without config, want error")
	}

	if n := env.desec.callCount(""); n != 0 {
		t.Errorf("got %d API calls, want 0", n)
	}
}

func TestCleanUpRemovesOnlyOwnValue(t *testing.T) {
	env := newTestEnv(t)
	env.desec.put(desec.RRSet{Domain: "example.com", SubName: "_acme-challenge", Type: "TXT", Records: []string{`"other"`, `"key1"`}})

	if err := env.solver.CleanUp(challenge("_acme-challenge.example.com.", "key1")); err != nil {
		t.Fatalf("CleanUp() error: %v", err)
	}

	rr, ok := env.desec.get("example.com", "_acme-challenge", "TXT")
	if !ok {
		t.Fatal("RRset was deleted although another value remained")
	}

	if !slices.Equal(rr.Records, []string{`"other"`}) {
		t.Errorf("records = %v, want [\"other\"]", rr.Records)
	}
}

func TestCleanUpDeletesLastValue(t *testing.T) {
	env := newTestEnv(t)
	env.desec.put(desec.RRSet{Domain: "example.com", SubName: "_acme-challenge", Type: "TXT", Records: []string{`"key1"`}})

	if err := env.solver.CleanUp(challenge("_acme-challenge.example.com.", "key1")); err != nil {
		t.Fatalf("CleanUp() error: %v", err)
	}

	if _, ok := env.desec.get("example.com", "_acme-challenge", "TXT"); ok {
		t.Error("RRset still exists after removing its last value")
	}
}

func TestCleanUpNothingToDo(t *testing.T) {
	t.Run("rrset missing", func(t *testing.T) {
		env := newTestEnv(t)

		if err := env.solver.CleanUp(challenge("_acme-challenge.example.com.", "key1")); err != nil {
			t.Fatalf("CleanUp() error: %v", err)
		}
	})

	t.Run("value missing", func(t *testing.T) {
		env := newTestEnv(t)
		env.desec.put(desec.RRSet{Domain: "example.com", SubName: "_acme-challenge", Type: "TXT", Records: []string{`"other"`}})

		if err := env.solver.CleanUp(challenge("_acme-challenge.example.com.", "key1")); err != nil {
			t.Fatalf("CleanUp() error: %v", err)
		}

		rr, _ := env.desec.get("example.com", "_acme-challenge", "TXT")
		if !slices.Equal(rr.Records, []string{`"other"`}) {
			t.Errorf("records = %v, want [\"other\"]", rr.Records)
		}

		if n := env.desec.callCount("PATCH") + env.desec.callCount("DELETE"); n != 0 {
			t.Errorf("got %d modifying requests, want 0", n)
		}
	})
}

func TestCleanUpReturnsAPIErrors(t *testing.T) {
	for _, failOn := range []string{"DELETE", "PATCH"} {
		t.Run(failOn, func(t *testing.T) {
			env := newTestEnv(t)

			records := []string{`"key1"`}
			if failOn == "PATCH" {
				records = append(records, `"other"`)
			}

			env.desec.put(desec.RRSet{Domain: "example.com", SubName: "_acme-challenge", Type: "TXT", Records: records})
			env.desec.failOn = failOn
			env.desec.failStatus = http.StatusInternalServerError

			if err := env.solver.CleanUp(challenge("_acme-challenge.example.com.", "key1")); err == nil {
				t.Fatal("CleanUp() returned nil, want error")
			}
		})
	}
}

// TestApexAndWildcard covers a certificate for example.com and *.example.com:
// both challenges use _acme-challenge.example.com with different keys.
func TestApexAndWildcard(t *testing.T) {
	env := newTestEnv(t)
	apex := challenge("_acme-challenge.example.com.", "apex-key")
	wildcard := challenge("_acme-challenge.example.com.", "wildcard-key")

	for _, ch := range []*v1alpha1.ChallengeRequest{apex, wildcard} {
		if err := env.solver.Present(ch); err != nil {
			t.Fatalf("Present(%s) error: %v", ch.Key, err)
		}
	}

	rr, _ := env.desec.get("example.com", "_acme-challenge", "TXT")
	if !slices.Equal(rr.Records, []string{`"apex-key"`, `"wildcard-key"`}) {
		t.Fatalf("records after Present = %v, want both keys", rr.Records)
	}

	if err := env.solver.CleanUp(apex); err != nil {
		t.Fatalf("CleanUp(apex) error: %v", err)
	}

	rr, _ = env.desec.get("example.com", "_acme-challenge", "TXT")
	if !slices.Equal(rr.Records, []string{`"wildcard-key"`}) {
		t.Fatalf("records after first CleanUp = %v, want only wildcard key", rr.Records)
	}

	if err := env.solver.CleanUp(wildcard); err != nil {
		t.Fatalf("CleanUp(wildcard) error: %v", err)
	}

	if _, ok := env.desec.get("example.com", "_acme-challenge", "TXT"); ok {
		t.Fatal("RRset still exists after both CleanUps")
	}
}

func TestApexRecord(t *testing.T) {
	// A zone delegated as _acme-challenge.example.com puts the record at the apex.
	env := newTestEnv(t, desec.Domain{Name: "_acme-challenge.example.com"})
	ch := challenge("_acme-challenge.example.com.", "key1")

	if err := env.solver.Present(ch); err != nil {
		t.Fatalf("Present() error: %v", err)
	}

	if _, ok := env.desec.get("_acme-challenge.example.com", "", "TXT"); !ok {
		t.Fatal("apex TXT RRset was not created")
	}

	if err := env.solver.CleanUp(ch); err != nil {
		t.Fatalf("CleanUp() error: %v", err)
	}

	if _, ok := env.desec.get("_acme-challenge.example.com", "", "TXT"); ok {
		t.Fatal("apex TXT RRset still exists after CleanUp")
	}
}

// TestConcurrentPresent makes sure concurrent challenges for the same name do
// not overwrite each other's values (read-modify-write of the RRset).
func TestConcurrentPresent(t *testing.T) {
	env := newTestEnv(t)

	const n = 10

	var wg sync.WaitGroup

	errs := make(chan error, n)

	for i := range n {
		wg.Go(func() {
			errs <- env.solver.Present(challenge("_acme-challenge.example.com.", fmt.Sprintf("key%d", i)))
		})
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("Present() error: %v", err)
		}
	}

	rr, _ := env.desec.get("example.com", "_acme-challenge", "TXT")
	if len(rr.Records) != n {
		t.Fatalf("got %d records, want %d: %v", len(rr.Records), n, rr.Records)
	}
}
