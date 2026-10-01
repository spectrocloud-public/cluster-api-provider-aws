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
	"github.com/aws/aws-sdk-go-v2/aws"
)

// fipsEndpointRegions are the regions in which AWS serves the FIPS 140-3
// endpoints that CAPA talks to.
//
// The SDK's generated endpoint rules decide FIPS support per partition rather
// than per region, and every region in the "aws" partition inherits
// supportsFIPS: true. So with FIPS requested, a region such as eu-west-1
// resolves to ec2-fips.eu-west-1.amazonaws.com, which does not exist and fails
// to resolve in DNS. Restricting the request to the regions below keeps every
// other region on its standard endpoints.
var fipsEndpointRegions = map[string]struct{}{
	"us-east-1":     {},
	"us-east-2":     {},
	"us-west-1":     {},
	"us-west-2":     {},
	"us-gov-east-1": {},
	"us-gov-west-1": {},
}

// FIPSEndpointStateForRegion returns the FIPS endpoint state to apply to an AWS
// config built for region.
//
// Regions that serve FIPS endpoints get aws.FIPSEndpointStateUnset, which
// leaves the SDK's own resolution chain (AWS_USE_FIPS_ENDPOINT, then
// use_fips_endpoint in the shared config) in charge. Every other region gets
// aws.FIPSEndpointStateDisabled, which takes precedence over both. The state is
// therefore only ever narrowed, never turned on for a caller who did not ask
// for it.
func FIPSEndpointStateForRegion(region string) aws.FIPSEndpointState {
	if _, ok := fipsEndpointRegions[region]; ok {
		return aws.FIPSEndpointStateUnset
	}
	return aws.FIPSEndpointStateDisabled
}
