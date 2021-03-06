package deploy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

var exampleConfig = `
deployment:
  stackName: "test"
  account: "123456789012"
  region: "us-east-1"
  release: "v0.1.0"
  parameters:
    CognitoDomainPrefix: ""

providers:
  okta:
    uses: "commonfate/okta@v1"
    with:
      orgUrl: "https://test.internal"
      apiToken: "awsssm:///granted/okta/apiToken"
`

func TestParseConfig(t *testing.T) {
	var c Config
	err := yaml.Unmarshal([]byte(exampleConfig), &c)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "commonfate/okta@v1", c.Providers["okta"].Uses)
}

func TestTestCfnParams(t *testing.T) {
	type testcase struct {
		name string
		give Config
		want string
	}

	testcases := []testcase{
		{
			name: "ok",
			give: Config{
				Deployment: Deployment{
					Parameters: Parameters{
						CognitoDomainPrefix: "test",
					},
				},
			},
			want: `[{"ParameterKey":"CognitoDomainPrefix","ParameterValue":"test","ResolvedValue":null,"UsePreviousValue":null}]`,
		},
		{
			name: "provider config",
			give: Config{
				Providers: map[string]Provider{
					"okta": {
						Uses: "commonfate/okta@v1",
						With: map[string]string{
							"orgUrl": "test.internal",
						},
					},
				},
			},
			want: `[{"ParameterKey":"CognitoDomainPrefix","ParameterValue":"","ResolvedValue":null,"UsePreviousValue":null},{"ParameterKey":"ProviderConfiguration","ParameterValue":"{\"okta\":{\"uses\":\"commonfate/okta@v1\",\"with\":{\"orgUrl\":\"test.internal\"}}}","ResolvedValue":null,"UsePreviousValue":null}]`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.give.CfnParams()
			if err != nil {
				t.Fatal(err)
			}
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, tc.want, string(gotJSON))
		})
	}
}

func TestUnmarshalIdentity(t *testing.T) {
	type testcase struct {
		name string
		give string
		want IdentityConfig
	}

	testcases := []testcase{
		{
			name: "empty",
			give: "",
			want: IdentityConfig{},
		},
		{
			name: "empty JSON",
			give: "{}",
			want: IdentityConfig{},
		},
		{
			name: "ok",
			give: `{"google": {"domain":"test"}}`,
			want: IdentityConfig{Google: &Google{
				Domain: "test",
			}},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UnmarshalIdentity(tc.give)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCfnTemplateURL(t *testing.T) {
	type testcase struct {
		name string
		give Config
		want string
	}

	testcases := []testcase{
		{
			name: "version tag",
			give: Config{
				Deployment: Deployment{
					Region:  "ap-southeast-2",
					Release: "v0.1.0",
				},
			},
			want: "https://granted-releases-ap-southeast-2.s3.amazonaws.com/v0.1.0/Granted.template.json",
		},
		{
			name: "custom URL",
			give: Config{
				Deployment: Deployment{
					Region:  "ap-southeast-2",
					Release: "https://custom-release.s3.amazonaws.com/template.json",
				},
			},
			want: "https://custom-release.s3.amazonaws.com/template.json",
		},
		{
			// note: this currently won't return an error, even though CloudFormation will refuse to deploy it.
			// this test captures this behaviour - in future we can add more validation around the URL.
			name: "custom URL not in S3",
			give: Config{
				Deployment: Deployment{
					Release: "https://some-other-url.com",
				},
			},
			want: "https://some-other-url.com",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.give.CfnTemplateURL()
			assert.Equal(t, tc.want, got)
		})
	}
}
