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

package identity

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	. "github.com/onsi/gomega"
)

// TestRoleProviderSTSEndpointHonoursFIPSRegionGating covers the AssumeRole leg
// of a role identity. It runs before the cluster session exists, so without the
// gating a role-based cluster in a non-FIPS region fails on a nonexistent STS
// FIPS endpoint rather than on the service call.
func TestRoleProviderSTSEndpointHonoursFIPSRegionGating(t *testing.T) {
	testCases := []struct {
		name     string
		region   string
		expected string
	}{
		{
			name:     "FIPS region keeps the FIPS STS endpoint",
			region:   "us-east-1",
			expected: "https://sts-fips.us-east-1.amazonaws.com",
		},
		{
			name:     "non-FIPS region falls back to the standard STS endpoint",
			region:   "eu-west-1",
			expected: "https://sts.eu-west-1.amazonaws.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			ctx := context.Background()

			t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "config"))
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials"))
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
			t.Setenv("AWS_PROFILE", "")
			t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")

			cfg, err := config.LoadDefaultConfig(ctx, configOptionsForRegion(tc.region)...)
			g.Expect(err).NotTo(HaveOccurred())

			opts := sts.NewFromConfig(cfg).Options()
			endpoint, err := sts.NewDefaultEndpointResolverV2().ResolveEndpoint(ctx, sts.EndpointParameters{
				Region:       aws.String(tc.region),
				UseFIPS:      aws.Bool(opts.EndpointOptions.UseFIPSEndpoint == aws.FIPSEndpointStateEnabled),
				UseDualStack: aws.Bool(false),
			})
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(endpoint.URI.String()).To(Equal(tc.expected))
		})
	}
}
