package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/nrdcg/desec"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const (
	// defaultTTL is used when deSEC does not report a minimum TTL for the domain.
	defaultTTL = 3600
	// requestTimeout bounds all deSEC API calls of a single Present/CleanUp.
	requestTimeout = 60 * time.Second
)

// desecDNSProviderSolver implements webhook.Solver for deSEC (desec.io).
type desecDNSProviderSolver struct {
	client kubernetes.Interface

	// newDesecClient creates the deSEC API client. It is a field so tests can
	// point the client at a fake API server.
	newDesecClient func(token string) *desec.Client

	// mu serialises Present and CleanUp. Both read, modify and write the
	// whole RRset, so concurrent challenges for the same name (apex and
	// wildcard of one certificate) would otherwise overwrite each other.
	mu sync.Mutex
}

// desecDNSProviderConfig is the solver configuration taken from the
// Issuer/ClusterIssuer (spec.acme.solvers[].dns01.webhook.config).
type desecDNSProviderConfig struct {
	APIKeySecretRef cmmeta.SecretKeySelector `json:"apiKeySecretRef"`
}

func newSolver() *desecDNSProviderSolver {
	return &desecDNSProviderSolver{
		newDesecClient: func(token string) *desec.Client {
			return desec.New(token, desec.NewDefaultClientOptions())
		},
	}
}

func (c *desecDNSProviderSolver) Name() string {
	return "desec"
}

func (c *desecDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// Present adds the challenge key to the TXT RRset of ch.ResolvedFQDN. Other
// values in the RRset are kept, so several challenges for the same name
// (e.g. example.com and *.example.com in one certificate) can coexist.
func (c *desecDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.V(1).Infof("presenting record %q", ch.ResolvedFQDN)

	c.mu.Lock()
	defer c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	api, err := c.apiClient(ctx, ch)
	if err != nil {
		return err
	}

	domain, subName, err := findRecordLocation(ctx, api, ch.ResolvedFQDN)
	if err != nil {
		return err
	}

	value := quoteTXT(ch.Key)

	existing, err := getTXT(ctx, api, domain.Name, subName)
	if err != nil {
		return err
	}

	if existing == nil {
		rrSet := desec.RRSet{
			Domain:  domain.Name,
			SubName: subName,
			Type:    "TXT",
			Records: []string{value},
			TTL:     ttlFor(domain),
		}

		if _, err := api.Records.Create(ctx, rrSet); err != nil {
			return fmt.Errorf("creating TXT record %q in domain %q: %w", subName, domain.Name, err)
		}

		klog.V(1).Infof("created TXT record %q in domain %q", subName, domain.Name)

		return nil
	}

	if slices.Contains(existing.Records, value) {
		klog.V(1).Infof("TXT record %q in domain %q already contains the challenge key", subName, domain.Name)
		return nil
	}

	records := append(slices.Clone(existing.Records), value)
	if _, err := api.Records.Update(ctx, domain.Name, subName, "TXT", desec.RRSet{Records: records}); err != nil {
		return fmt.Errorf("updating TXT record %q in domain %q: %w", subName, domain.Name, err)
	}

	klog.V(1).Infof("added challenge key to TXT record %q in domain %q", subName, domain.Name)

	return nil
}

// CleanUp removes the challenge key from the TXT RRset of ch.ResolvedFQDN.
// The RRset is only deleted when no other values remain.
func (c *desecDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.V(1).Infof("cleaning up record %q", ch.ResolvedFQDN)

	c.mu.Lock()
	defer c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	api, err := c.apiClient(ctx, ch)
	if err != nil {
		return err
	}

	domain, subName, err := findRecordLocation(ctx, api, ch.ResolvedFQDN)
	if err != nil {
		return err
	}

	existing, err := getTXT(ctx, api, domain.Name, subName)
	if err != nil {
		return err
	}

	value := quoteTXT(ch.Key)
	if existing == nil || !slices.Contains(existing.Records, value) {
		klog.V(1).Infof("TXT record %q in domain %q holds no challenge key, nothing to clean up", subName, domain.Name)
		return nil
	}

	remaining := slices.DeleteFunc(slices.Clone(existing.Records), func(r string) bool { return r == value })
	if len(remaining) == 0 {
		if err := api.Records.Delete(ctx, domain.Name, subName, "TXT"); err != nil {
			return fmt.Errorf("deleting TXT record %q in domain %q: %w", subName, domain.Name, err)
		}

		klog.V(1).Infof("deleted TXT record %q in domain %q", subName, domain.Name)

		return nil
	}

	if _, err := api.Records.Update(ctx, domain.Name, subName, "TXT", desec.RRSet{Records: remaining}); err != nil {
		return fmt.Errorf("updating TXT record %q in domain %q: %w", subName, domain.Name, err)
	}

	klog.V(1).Infof("removed challenge key from TXT record %q in domain %q", subName, domain.Name)

	return nil
}

// apiClient loads the solver config and returns a deSEC client using the
// token from the referenced secret.
func (c *desecDNSProviderSolver) apiClient(ctx context.Context, ch *v1alpha1.ChallengeRequest) (*desec.Client, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	token, err := c.getSecretKey(ctx, cfg.APIKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, err
	}

	return c.newDesecClient(token), nil
}

func loadConfig(cfgJSON *extapi.JSON) (desecDNSProviderConfig, error) {
	cfg := desecDNSProviderConfig{}

	if cfgJSON == nil {
		return cfg, errors.New("solver config is missing, apiKeySecretRef is required")
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("decoding solver config: %w", err)
	}

	if cfg.APIKeySecretRef.Name == "" {
		return cfg, errors.New("solver config: apiKeySecretRef.name is required")
	}

	if cfg.APIKeySecretRef.Key == "" {
		return cfg, errors.New("solver config: apiKeySecretRef.key is required")
	}

	return cfg, nil
}

// getSecretKey reads a single key from a secret in the given namespace.
func (c *desecDNSProviderSolver) getSecretKey(ctx context.Context, ref cmmeta.SecretKeySelector, namespace string) (string, error) {
	klog.V(5).Infof("retrieving key %q in secret %s/%s", ref.Key, namespace, ref.Name)

	sec, err := c.client.CoreV1().Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("getting secret %s/%s: %w", namespace, ref.Name, err)
	}

	data, ok := sec.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", ref.Key, namespace, ref.Name)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("key %q in secret %s/%s is empty", ref.Key, namespace, ref.Name)
	}

	return token, nil
}

// findRecordLocation asks deSEC which of the account's domains is responsible
// for fqdn and returns that domain together with the subname relative to it.
func findRecordLocation(ctx context.Context, api *desec.Client, fqdn string) (*desec.Domain, string, error) {
	name := util.UnFqdn(fqdn)

	domain, err := api.Domains.GetResponsible(ctx, name)
	if err != nil {
		var notFound *desec.NotFoundError
		if errors.As(err, &notFound) {
			return nil, "", fmt.Errorf("no deSEC domain in this account is responsible for %q", name)
		}

		return nil, "", fmt.Errorf("looking up responsible domain for %q: %w", name, err)
	}

	subName, err := subNameFor(name, domain.Name)
	if err != nil {
		return nil, "", err
	}

	return domain, subName, nil
}

// subNameFor returns the part of name below zone. It returns "" for the zone
// apex and an error if name is not inside zone.
func subNameFor(name, zone string) (string, error) {
	name = strings.ToLower(util.UnFqdn(name))
	zone = strings.ToLower(util.UnFqdn(zone))

	if name == zone {
		return "", nil
	}

	if sub, ok := strings.CutSuffix(name, "."+zone); ok && sub != "" {
		return sub, nil
	}

	return "", fmt.Errorf("%q is not inside zone %q", name, zone)
}

// getTXT returns the TXT RRset or nil if it does not exist.
func getTXT(ctx context.Context, api *desec.Client, domain, subName string) (*desec.RRSet, error) {
	rrSet, err := api.Records.Get(ctx, domain, subName, "TXT")
	if err != nil {
		var notFound *desec.NotFoundError
		if errors.As(err, &notFound) {
			return nil, nil
		}

		return nil, fmt.Errorf("getting TXT record %q in domain %q: %w", subName, domain, err)
	}

	return rrSet, nil
}

func ttlFor(domain *desec.Domain) int {
	if domain.MinimumTTL > 0 {
		return domain.MinimumTTL
	}

	return defaultTTL
}

func quoteTXT(value string) string {
	return `"` + value + `"`
}
