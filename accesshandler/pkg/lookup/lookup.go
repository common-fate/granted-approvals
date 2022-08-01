package lookup

import (
	"fmt"
	"regexp"

	"github.com/common-fate/granted-approvals/accesshandler/pkg/providers"
	"github.com/common-fate/granted-approvals/accesshandler/pkg/providers/aws/sso"
	"github.com/common-fate/granted-approvals/accesshandler/pkg/providers/azure/ad"
	"github.com/common-fate/granted-approvals/accesshandler/pkg/providers/okta"
	"github.com/common-fate/granted-approvals/accesshandler/pkg/providers/testvault"
	"github.com/fatih/color"
)

type ProviderRegistry struct {
	Providers map[string]RegisteredProvider
}

func Registry() ProviderRegistry {
	return ProviderRegistry{
		Providers: map[string]RegisteredProvider{
			"commonfate/okta@v1": {
				Provider:    &okta.Provider{},
				DefaultID:   "okta",
				Description: "Okta groups",
			},
			"commonfate/azure-ad@v1": {
				Provider:    &ad.Provider{},
				DefaultID:   "azure-ad",
				Description: "Azure-AD groups",
			},
			"commonfate/aws-sso@v1": {
				Provider:    &sso.Provider{},
				DefaultID:   "aws-sso",
				Description: "AWS SSO PermissionSets",
			},
			"commonfate/testvault@v1": {
				Provider:    &testvault.Provider{},
				DefaultID:   "testvault",
				Description: "TestVault - a provider for testing out Granted Approvals",
			},
		},
	}
}

// Lookup a provider by the 'uses' string.
func (r ProviderRegistry) Lookup(uses string) (*RegisteredProvider, error) {
	p, ok := r.Providers[uses]
	if !ok {
		return nil, fmt.Errorf("could not find provider %s", uses)
	}
	return &p, nil
}

func (r ProviderRegistry) CLIOptions() []string {
	var opts []string
	keys := make([]string, 0, len(r.Providers))
	for k := range r.Providers {
		keys = append(keys, k)
	}

	for _, v := range keys {
		prov := r.Providers[v]
		grey := color.New(color.FgHiBlack).SprintFunc()
		id := "(" + v + ")"
		opt := fmt.Sprintf("%s %s", prov.Description, grey(id))
		opts = append(opts, opt)
	}
	return opts
}

func (r ProviderRegistry) FromCLIOption(opt string) (key string, p RegisteredProvider, err error) {
	re, err := regexp.Compile(`[\w ]+\((.*)\)`)
	if err != nil {
		return "", RegisteredProvider{}, err
	}
	got := re.FindStringSubmatch(opt)
	if got == nil {
		return "", RegisteredProvider{}, fmt.Errorf("couldn't extract provider key: %s", opt)
	}
	key = got[1]
	p, ok := r.Providers[key]
	if !ok {
		return "", RegisteredProvider{}, fmt.Errorf("couldn't find provider with key: %s", key)
	}
	return key, p, nil
}

type RegisteredProvider struct {
	Provider    providers.Accessor
	DefaultID   string
	Description string
}
