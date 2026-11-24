GO ?= go

IMAGE_NAME ?= cert-manager-desec-webhook
IMAGE_TAG ?= dev

OUT := $(shell pwd)/_out
CHART_DIR := deploy/desec-webhook

# Kubernetes version of the envtest binaries for the conformance tests.
ENVTEST_K8S_VERSION ?= 1.36.x
ENVTEST_DIR := $(shell pwd)/_test/envtest
SETUP_ENVTEST := $(GO) run sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.24

.PHONY: test
test:
	$(GO) vet ./...
	$(GO) test -race -cover ./...

# Runs the cert-manager DNS01 conformance suite against the real deSEC API.
# Needs TEST_ZONE_NAME (e.g. example.com.) and DESEC_TOKEN.
.PHONY: test-conformance
test-conformance:
	@test -n "$(TEST_ZONE_NAME)" || (echo "TEST_ZONE_NAME is not set" && exit 1)
	@test -n "$$DESEC_TOKEN" || (echo "DESEC_TOKEN is not set" && exit 1)
	ASSETS="$$($(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(ENVTEST_DIR) -p path)" && \
	TEST_ASSET_ETCD="$$ASSETS/etcd" \
	TEST_ASSET_KUBE_APISERVER="$$ASSETS/kube-apiserver" \
	TEST_ASSET_KUBECTL="$$ASSETS/kubectl" \
	$(GO) test -tags conformance -run TestConformance -count=1 -v .

.PHONY: lint-chart
lint-chart:
	helm lint --strict $(CHART_DIR)

.PHONY: build
build:
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)" .

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml: | $(OUT)
	helm template desec-webhook \
	    --set image.repository=$(IMAGE_NAME) \
	    --set image.tag=$(IMAGE_TAG) \
	    $(CHART_DIR) > $(OUT)/rendered-manifest.yaml

.PHONY: clean
clean:
	rm -rf _test $(OUT)

$(OUT):
	mkdir -p $@
