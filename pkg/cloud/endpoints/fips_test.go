/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package endpoints

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/onsi/gomega"
)

func TestFIPSEndpointStateForRegion(t *testing.T) {
	testCases := []struct {
		name     string
		region   string
		expected aws.FIPSEndpointState
	}{
		{
			name:     "us-east-1 serves FIPS endpoints",
			region:   "us-east-1",
			expected: aws.FIPSEndpointStateUnset,
		},
		{
			name:     "us-west-2 serves FIPS endpoints",
			region:   "us-west-2",
			expected: aws.FIPSEndpointStateUnset,
		},
		{
			name:     "us-gov-west-1 serves FIPS endpoints",
			region:   "us-gov-west-1",
			expected: aws.FIPSEndpointStateUnset,
		},
		{
			name:     "eu-west-1 does not serve FIPS endpoints",
			region:   "eu-west-1",
			expected: aws.FIPSEndpointStateDisabled,
		},
		{
			name:     "ap-south-1 does not serve FIPS endpoints",
			region:   "ap-south-1",
			expected: aws.FIPSEndpointStateDisabled,
		},
		{
			name:     "us-iso-east-1 does not serve FIPS endpoints",
			region:   "us-iso-east-1",
			expected: aws.FIPSEndpointStateDisabled,
		},
		{
			name:     "us-isob-east-1 does not serve FIPS endpoints",
			region:   "us-isob-east-1",
			expected: aws.FIPSEndpointStateDisabled,
		},
		{
			name:     "empty region defers to the SDK resolution chain",
			region:   "",
			expected: aws.FIPSEndpointStateUnset,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			g.Expect(FIPSEndpointStateForRegion(tc.region)).To(gomega.Equal(tc.expected))
		})
	}
}

// TestFIPSEndpointResolutionWithEnv covers the behaviour that actually broke:
// AWS_USE_FIPS_ENDPOINT is set process-wide in FIPS deployments, and without
// the per-region state a non-FIPS region resolves to a hostname that does not
// exist.
func TestFIPSEndpointResolutionWithEnv(t *testing.T) {
	testCases := []struct {
		name     string
		region   string
		expected string
	}{
		{
			name:     "FIPS region keeps the FIPS endpoint",
			region:   "us-east-1",
			expected: "https://ec2-fips.us-east-1.amazonaws.com",
		},
		{
			name:     "non-FIPS region falls back to the standard endpoint",
			region:   "eu-west-1",
			expected: "https://ec2.eu-west-1.amazonaws.com",
		},
		{
			name:     "GovCloud resolves to its standard hostname, which is FIPS",
			region:   "us-gov-west-1",
			expected: "https://ec2.us-gov-west-1.amazonaws.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			ctx := context.Background()

			isolateAWSEnv(t)
			t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")

			cfg, err := config.LoadDefaultConfig(ctx,
				config.WithRegion(tc.region),
				config.WithUseFIPSEndpoint(FIPSEndpointStateForRegion(tc.region)),
			)
			g.Expect(err).NotTo(gomega.HaveOccurred())

			opts := ec2.NewFromConfig(cfg).Options()
			endpoint, err := ec2.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, ec2.EndpointParameters{
				Region:       aws.String(tc.region),
				UseFIPS:      aws.Bool(opts.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateEnabled),
				UseDualStack: aws.Bool(false),
			})
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(endpoint.URI.String()).To(gomega.Equal(tc.expected))
		})
	}
}

// TestFIPSEndpointResolutionWithoutEnv asserts the state function never turns
// FIPS on for a caller who did not ask for it.
func TestFIPSEndpointResolutionWithoutEnv(t *testing.T) {
	for _, region := range []string{"us-east-1", "eu-west-1"} {
		t.Run(region, func(t *testing.T) {
			g := gomega.NewWithT(t)
			ctx := context.Background()

			isolateAWSEnv(t)

			cfg, err := config.LoadDefaultConfig(ctx,
				config.WithRegion(region),
				config.WithUseFIPSEndpoint(FIPSEndpointStateForRegion(region)),
			)
			g.Expect(err).NotTo(gomega.HaveOccurred())

			opts := ec2.NewFromConfig(cfg).Options()
			g.Expect(opts.EndpointOptions.UseFIPSEndpoint).NotTo(gomega.Equal(aws.FIPSEndpointStateEnabled))
		})
	}
}

// isolateAWSEnv keeps endpoint resolution from picking up the ambient AWS
// configuration of whoever runs the tests.
func isolateAWSEnv(t *testing.T) {
	t.Helper()

	t.Setenv("AWS_USE_FIPS_ENDPOINT", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_PROFILE", "")
}
