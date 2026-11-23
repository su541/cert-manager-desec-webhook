//go:build conformance

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
)

// TestConformance runs the cert-manager DNS01 conformance suite against the
// real deSEC API. It needs:
//
//	TEST_ZONE_NAME  a deSEC domain of the account, with trailing dot (example.com.)
//	DESEC_TOKEN     a deSEC API token allowed to change TXT records in that domain
//
// and the envtest binaries (etcd, kube-apiserver, kubectl), see `make test-conformance`.
func TestConformance(t *testing.T) {
	zone := os.Getenv("TEST_ZONE_NAME")
	token := os.Getenv("DESEC_TOKEN")

	if zone == "" || token == "" {
		t.Skip("TEST_ZONE_NAME and DESEC_TOKEN must be set to run the conformance tests")
	}

	// Write the solver config and the token secret into a temporary manifest
	// directory, so the token never ends up in the repository.
	manifests := t.TempDir()

	config := `{"apiKeySecretRef":{"name":"desec-token","key":"token"}}`
	if err := os.WriteFile(filepath.Join(manifests, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	secret := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: desec-token
type: Opaque
data:
  token: %s
`, base64.StdEncoding.EncodeToString([]byte(token)))
	if err := os.WriteFile(filepath.Join(manifests, "secret.yaml"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	fixture := acmetest.NewFixture(newSolver(),
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath(manifests),
		acmetest.SetStrict(true),
		acmetest.SetDNSServer("ns1.desec.io:53"),
		acmetest.SetUseAuthoritative(false),
	)

	fixture.RunConformance(t)
}
