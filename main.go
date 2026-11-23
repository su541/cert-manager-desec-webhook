package main

import (
	"os"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

// GroupName is the API group under which the webhook is registered. It must
// match the groupName configured in the Issuer/ClusterIssuer.
var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName, newSolver())
}
