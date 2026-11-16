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

// Package spectrofakeaws is a Spectro fork-only test helper (PCP-7927). It fakes STS AssumeRole and the EC2
// Describe* calls over HTTP and records which access key signed each request, so tests can assert which
// credentials a controller used. Point the AWS SDK at it with AWS_ENDPOINT_URL.
package spectrofakeaws

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
)

const (
	// ControllerKey is the access key a test should give the controller's own (default chain) credentials.
	ControllerKey = "AKIACONTROLLERBASE00"
	// AssumedKey is the access key the fake AssumeRole hands back for the cluster's role.
	AssumedKey = "ASIAASSUMEDCLUSTER00"
)

var credentialRe = regexp.MustCompile(`Credential=([A-Z0-9]+)/`)

// Call is one recorded request.
type Call struct{ Action, Signer string }

// Server is the fake AWS endpoint.
type Server struct {
	URL string

	mu    sync.Mutex
	calls []Call
}

// Calls returns a copy of the recorded requests, in arrival order.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// New starts the fake and stops it when the test ends. EC2 DescribeInstanceTypes returns one x86_64
// instance type with 2 vCPUs and 8192 MiB.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action := r.Form.Get("Action")
		signer := ""
		if m := credentialRe.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
			signer = m[1]
		}
		s.mu.Lock()
		s.calls = append(s.calls, Call{action, signer})
		s.mu.Unlock()

		w.Header().Set("Content-Type", "text/xml")
		switch action {
		case "AssumeRole":
			fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult>
<Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>
<AssumedRoleUser><AssumedRoleId>AROA:s</AssumedRoleId><Arn>arn:aws:sts::111122223333:assumed-role/customer/s</Arn></AssumedRoleUser>
</AssumeRoleResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></AssumeRoleResponse>`, AssumedKey)
		case "DescribeInstanceTypes":
			fmt.Fprint(w, `<DescribeInstanceTypesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>r</requestId><instanceTypeSet><item>
<instanceType>t3.large</instanceType><vCpuInfo><defaultVCpus>2</defaultVCpus></vCpuInfo><memoryInfo><sizeInMiB>8192</sizeInMiB></memoryInfo>
<processorInfo><supportedArchitectures><item>x86_64</item></supportedArchitectures></processorInfo>
</item></instanceTypeSet></DescribeInstanceTypesResponse>`)
		default:
			fmt.Fprintf(w, `<%[1]sResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>r</requestId></%[1]sResponse>`, action)
		}
	}))
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	return s
}

// SetControllerCredentials points the AWS SDK default chain at this fake with the controller's own key and
// disables every other credential source. It uses t.Setenv, so the test must not be parallel.
func (s *Server) SetControllerCredentials(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ENDPOINT_URL", s.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", ControllerKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
}

// EC2Signers returns the signing access key of every DescribeInstanceTypes/DescribeImages call.
func (s *Server) EC2Signers() []string {
	var out []string
	for _, c := range s.Calls() {
		if c.Action == "DescribeInstanceTypes" || c.Action == "DescribeImages" {
			out = append(out, c.Signer)
		}
	}
	return out
}

// Assumed reports whether the role was assumed at least once.
func (s *Server) Assumed() bool {
	for _, c := range s.Calls() {
		if c.Action == "AssumeRole" {
			return true
		}
	}
	return false
}
