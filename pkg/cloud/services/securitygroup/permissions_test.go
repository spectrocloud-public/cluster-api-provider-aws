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

package securitygroup

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	. "github.com/onsi/gomega"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
)

func TestIngressRulePermissionIdentity(t *testing.T) {
	tests := []struct {
		name                 string
		self                 infrav1.IngressRules
		input                infrav1.IngressRules
		wantDifference       int
		wantDeduped          int
		wantFirstDescription string
	}{
		{
			name: "description is not part of the permission identity",
			self: infrav1.IngressRules{
				{
					Description: "VPC access",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
			},
			input: infrav1.IngressRules{
				{
					Description: "Kubernetes API",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
			},
			wantDifference:       0,
			wantDeduped:          1,
			wantFirstDescription: "VPC access",
		},
		{
			name: "duplicate permissions keep the first rule",
			self: infrav1.IngressRules{
				{
					Description: "first",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
				{
					Description: "second",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
			},
			wantDifference:       2,
			wantDeduped:          1,
			wantFirstDescription: "first",
		},
		{
			name: "distinct protocol, port and source are preserved",
			self: infrav1.IngressRules{
				{
					Description: "tcp 6443",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
				{
					Description: "tcp 6444",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6444,
					ToPort:      6444,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
				{
					Description: "udp 6443",
					Protocol:    infrav1.SecurityGroupProtocolUDP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
				{
					Description:            "from source SG",
					Protocol:               infrav1.SecurityGroupProtocolTCP,
					FromPort:               6443,
					ToPort:                 6443,
					SourceSecurityGroupIDs: []string{"sg-source"},
				},
			},
			wantDifference: 4,
			wantDeduped:    4,
		},
		{
			name: "wildcard protocol ignores ports",
			self: infrav1.IngressRules{
				{
					Description: "wildcard zero ports",
					Protocol:    infrav1.SecurityGroupProtocolAll,
					FromPort:    0,
					ToPort:      0,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
				{
					Description: "wildcard api port",
					Protocol:    infrav1.SecurityGroupProtocolAll,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
			},
			wantDifference: 2,
			wantDeduped:    1,
		},
		{
			name: "AWS-canonical CIDRs are the same permission",
			self: infrav1.IngressRules{
				{
					Description: "noncanonical",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.50.0.1/16"},
				},
				{
					Description: "canonical",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.50.0.0/16"},
				},
			},
			wantDifference: 2,
			wantDeduped:    1,
		},
		{
			name: "grouped and expanded CIDR rules have different identities",
			self: infrav1.IngressRules{
				{
					Description: "grouped",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16", "10.1.0.0/16"},
				},
				{
					Description: "expanded",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
			},
			wantDifference: 2,
			wantDeduped:    2,
		},
		{
			name: "source security group roles are distinct when unresolved",
			self: infrav1.IngressRules{
				{
					Description:              "node role",
					Protocol:                 infrav1.SecurityGroupProtocolTCP,
					FromPort:                 6443,
					ToPort:                   6443,
					SourceSecurityGroupRoles: []infrav1.SecurityGroupRole{infrav1.SecurityGroupNode},
				},
				{
					Description:              "node and controlplane roles",
					Protocol:                 infrav1.SecurityGroupProtocolTCP,
					FromPort:                 6443,
					ToPort:                   6443,
					SourceSecurityGroupRoles: []infrav1.SecurityGroupRole{infrav1.SecurityGroupNode, infrav1.SecurityGroupControlPlane},
				},
			},
			wantDifference: 2,
			wantDeduped:    2,
		},
		{
			name: "roles are ignored when CIDRs are present",
			self: infrav1.IngressRules{
				{
					Description:              "node role",
					Protocol:                 infrav1.SecurityGroupProtocolTCP,
					FromPort:                 6443,
					ToPort:                   6443,
					CidrBlocks:               []string{"10.0.0.0/16"},
					SourceSecurityGroupRoles: []infrav1.SecurityGroupRole{infrav1.SecurityGroupNode},
				},
				{
					Description:              "controlplane role",
					Protocol:                 infrav1.SecurityGroupProtocolTCP,
					FromPort:                 6443,
					ToPort:                   6443,
					CidrBlocks:               []string{"10.0.0.0/16"},
					SourceSecurityGroupRoles: []infrav1.SecurityGroupRole{infrav1.SecurityGroupControlPlane},
				},
			},
			wantDifference: 2,
			wantDeduped:    1,
		},
		{
			name: "resolved roles are keyed by their source security group IDs",
			self: infrav1.IngressRules{
				{
					Description:              "resolved node",
					Protocol:                 infrav1.SecurityGroupProtocolTCP,
					FromPort:                 6443,
					ToPort:                   6443,
					SourceSecurityGroupIDs:   []string{"sg-node"},
					SourceSecurityGroupRoles: []infrav1.SecurityGroupRole{infrav1.SecurityGroupNode},
				},
				{
					Description:            "node ID only",
					Protocol:               infrav1.SecurityGroupProtocolTCP,
					FromPort:               6443,
					ToPort:                 6443,
					SourceSecurityGroupIDs: []string{"sg-node"},
				},
			},
			wantDifference: 2,
			wantDeduped:    1,
		},
		{
			name: "distinct resolved role sources have distinct IDs",
			self: infrav1.IngressRules{
				{
					Description:              "node role resolved",
					Protocol:                 infrav1.SecurityGroupProtocolTCP,
					FromPort:                 6443,
					ToPort:                   6443,
					SourceSecurityGroupIDs:   []string{"sg-shared", "sg-node"},
					SourceSecurityGroupRoles: []infrav1.SecurityGroupRole{infrav1.SecurityGroupNode},
				},
				{
					Description:              "controlplane role resolved",
					Protocol:                 infrav1.SecurityGroupProtocolTCP,
					FromPort:                 6443,
					ToPort:                   6443,
					SourceSecurityGroupIDs:   []string{"sg-shared", "sg-controlplane"},
					SourceSecurityGroupRoles: []infrav1.SecurityGroupRole{infrav1.SecurityGroupControlPlane},
				},
			},
			wantDifference: 2,
			wantDeduped:    2,
		},
		{
			name: "CIDRs and source security group IDs are distinct sources",
			self: infrav1.IngressRules{
				{
					Description:            "cidr with sg a",
					Protocol:               infrav1.SecurityGroupProtocolTCP,
					FromPort:               6443,
					ToPort:                 6443,
					CidrBlocks:             []string{"10.0.0.0/16"},
					SourceSecurityGroupIDs: []string{"sg-a"},
				},
				{
					Description:            "cidr with sg b",
					Protocol:               infrav1.SecurityGroupProtocolTCP,
					FromPort:               6443,
					ToPort:                 6443,
					CidrBlocks:             []string{"10.0.0.0/16"},
					SourceSecurityGroupIDs: []string{"sg-b"},
				},
			},
			wantDifference: 2,
			wantDeduped:    2,
		},
		{
			name: "a mixed CIDR and source SG rule is distinct from the CIDR-only rule",
			self: infrav1.IngressRules{
				{
					Description:            "mixed",
					Protocol:               infrav1.SecurityGroupProtocolTCP,
					FromPort:               6443,
					ToPort:                 6443,
					CidrBlocks:             []string{"10.0.0.0/16"},
					SourceSecurityGroupIDs: []string{"sg-a"},
				},
				{
					Description: "cidr only",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
			},
			wantDifference: 2,
			wantDeduped:    2,
		},
		{
			name: "ICMP types are distinct",
			self: infrav1.IngressRules{
				{
					Description: "echo request",
					Protocol:    infrav1.SecurityGroupProtocolICMP,
					FromPort:    8,
					ToPort:      0,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
				{
					Description: "echo reply",
					Protocol:    infrav1.SecurityGroupProtocolICMP,
					FromPort:    0,
					ToPort:      0,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
			},
			wantDifference: 2,
			wantDeduped:    2,
		},
		{
			name: "IPv4 and IPv6 sources are distinct",
			self: infrav1.IngressRules{
				{
					Description: "ipv4",
					Protocol:    infrav1.SecurityGroupProtocolTCP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
				{
					Description:    "ipv6",
					Protocol:       infrav1.SecurityGroupProtocolTCP,
					FromPort:       6443,
					ToPort:         6443,
					IPv6CidrBlocks: []string{"2001:db8::/32"},
				},
			},
			wantDifference: 2,
			wantDeduped:    2,
		},
		{
			name: "IP-in-IP and ESP ignore ports",
			self: infrav1.IngressRules{
				{
					Description: "ipip zero",
					Protocol:    infrav1.SecurityGroupProtocolIPinIP,
					FromPort:    0,
					ToPort:      0,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
				{
					Description: "ipip api port",
					Protocol:    infrav1.SecurityGroupProtocolIPinIP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
				{
					Description: "esp zero",
					Protocol:    infrav1.SecurityGroupProtocolESP,
					FromPort:    0,
					ToPort:      0,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
				{
					Description: "esp api port",
					Protocol:    infrav1.SecurityGroupProtocolESP,
					FromPort:    6443,
					ToPort:      6443,
					CidrBlocks:  []string{"10.0.0.0/16"},
				},
			},
			wantDifference: 4,
			wantDeduped:    2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGomegaWithT(t)
			g.Expect(differenceByPermission(tc.self, tc.input)).To(HaveLen(tc.wantDifference))

			deduped := dedupeByPermission(tc.self)
			g.Expect(deduped).To(HaveLen(tc.wantDeduped))
			if tc.wantFirstDescription != "" {
				g.Expect(deduped[0].Description).To(Equal(tc.wantFirstDescription))
			}
		})
	}
}

func TestPermissionKeyEquivalence(t *testing.T) {
	tcp := func(mod func(*infrav1.IngressRule)) infrav1.IngressRule {
		r := infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolTCP, FromPort: 6443, ToPort: 6443}
		mod(&r)
		return r
	}
	tests := []struct {
		name string
		a, b infrav1.IngressRule
		same bool
	}{
		{
			name: "host bits in a CIDR are masked like AWS does",
			a:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"10.50.0.1/16"} }),
			b:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"10.50.0.0/16"} }),
			same: true,
		},
		{
			name: "IPv6 case and zero compression are canonicalized",
			a:    tcp(func(r *infrav1.IngressRule) { r.IPv6CidrBlocks = []string{"2001:DB8:0::/32"} }),
			b:    tcp(func(r *infrav1.IngressRule) { r.IPv6CidrBlocks = []string{"2001:db8::/32"} }),
			same: true,
		},
		{
			name: "source order inside a rule does not matter",
			a:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"10.0.0.0/24", "10.0.1.0/24"} }),
			b:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"10.0.1.0/24", "10.0.0.0/24"} }),
			same: true,
		},
		{
			name: "protocol case does not matter",
			a:    infrav1.IngressRule{Protocol: "TCP", FromPort: 22, ToPort: 22, CidrBlocks: []string{"10.0.0.0/8"}},
			b:    infrav1.IngressRule{Protocol: "tcp", FromPort: 22, ToPort: 22, CidrBlocks: []string{"10.0.0.0/8"}},
			same: true,
		},
		{
			name: "IPv4 and IPv6 sources are distinct",
			a:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"10.50.0.0/16"} }),
			b:    tcp(func(r *infrav1.IngressRule) { r.IPv6CidrBlocks = []string{"2001:db8::/32"} }),
		},
		{
			name: "CIDR and source security group are distinct",
			a:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"10.50.0.0/16"} }),
			b:    tcp(func(r *infrav1.IngressRule) { r.SourceSecurityGroupIDs = []string{"sg-abc"} }),
		},
		{
			name: "roles are ignored when CIDRs are present",
			a: tcp(func(r *infrav1.IngressRule) {
				r.CidrBlocks = []string{"10.50.0.0/16"}
				r.SourceSecurityGroupRoles = []infrav1.SecurityGroupRole{infrav1.SecurityGroupNode}
			}),
			b:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"10.50.0.0/16"} }),
			same: true,
		},
		{
			name: "overlapping port ranges are separate permissions in AWS",
			a:    infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolTCP, FromPort: 6443, ToPort: 6443, CidrBlocks: []string{"0.0.0.0/0"}},
			b:    infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolTCP, FromPort: 0, ToPort: 65535, CidrBlocks: []string{"0.0.0.0/0"}},
		},
		{
			name: "ICMPv6 keeps its type and code",
			a:    infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolICMPv6, FromPort: 128, ToPort: -1, CidrBlocks: []string{"::/0"}},
			b:    infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolICMPv6, FromPort: 129, ToPort: -1, CidrBlocks: []string{"::/0"}},
		},
		{
			name: "ICMP all codes differs from a specific code",
			a:    infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolICMP, FromPort: -1, ToPort: -1, CidrBlocks: []string{"10.0.0.0/8"}},
			b:    infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolICMP, FromPort: 8, ToPort: 0, CidrBlocks: []string{"10.0.0.0/8"}},
		},
		{
			name: "an out of range prefix length is kept as written",
			a:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"10.0.0.0/33"} }),
			b:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"10.0.0.0/32"} }),
		},
		{
			name: "surrounding whitespace is not trimmed, AWS rejects such a CIDR anyway",
			a:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{" 10.0.0.0/8"} }),
			b:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"10.0.0.0/8"} }),
		},
		{
			name: "invalid CIDR does not panic and stays distinct from a valid one",
			a:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"not-a-cidr"} }),
			b:    tcp(func(r *infrav1.IngressRule) { r.CidrBlocks = []string{"10.0.0.0/8"} }),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			if tc.same {
				g.Expect(permissionKey(tc.a)).To(Equal(permissionKey(tc.b)))
			} else {
				g.Expect(permissionKey(tc.a)).NotTo(Equal(permissionKey(tc.b)))
			}
		})
	}
}

func TestDedupeAfterExpand(t *testing.T) {
	rule := func(desc string, cidrs []string, ids []string) infrav1.IngressRule {
		return infrav1.IngressRule{
			Description:            desc,
			Protocol:               infrav1.SecurityGroupProtocolTCP,
			FromPort:               6443,
			ToPort:                 6443,
			CidrBlocks:             cidrs,
			SourceSecurityGroupIDs: ids,
		}
	}
	sources := func(rules infrav1.IngressRules) []string {
		out := []string{}
		for _, r := range rules {
			out = append(out, r.CidrBlocks...)
			out = append(out, r.SourceSecurityGroupIDs...)
		}
		return out
	}

	tests := []struct {
		name  string
		rules infrav1.IngressRules
		want  []string
	}{
		{
			name:  "repeated CIDR inside one rule collapses",
			rules: infrav1.IngressRules{rule("a", []string{"10.0.0.0/24", "10.0.0.0/24"}, nil)},
			want:  []string{"10.0.0.0/24"},
		},
		{
			name:  "non-canonical repeat collapses",
			rules: infrav1.IngressRules{rule("a", []string{"10.0.0.0/24", "10.0.0.7/24"}, nil)},
			want:  []string{"10.0.0.0/24"},
		},
		{
			name: "grouped rule followed by a repeated member keeps every source once",
			rules: infrav1.IngressRules{
				rule("group", []string{"10.0.0.1/32", "10.0.0.2/32"}, nil),
				rule("single", []string{"10.0.0.2/32"}, nil),
			},
			want: []string{"10.0.0.1/32", "10.0.0.2/32"},
		},
		{
			name: "single member followed by the group keeps every source once",
			rules: infrav1.IngressRules{
				rule("single", []string{"10.0.0.2/32"}, nil),
				rule("group", []string{"10.0.0.1/32", "10.0.0.2/32"}, nil),
			},
			want: []string{"10.0.0.2/32", "10.0.0.1/32"},
		},
		{
			name:  "CIDR plus explicit source security group emits both permissions",
			rules: infrav1.IngressRules{rule("a", []string{"10.0.0.0/24"}, []string{"sg-1"})},
			want:  []string{"10.0.0.0/24", "sg-1"},
		},
		{
			name: "two sourceless rules for the same port collapse",
			rules: infrav1.IngressRules{
				{Description: "a", Protocol: infrav1.SecurityGroupProtocolTCP, FromPort: 9000, ToPort: 9000},
				{Description: "b", Protocol: infrav1.SecurityGroupProtocolTCP, FromPort: 9000, ToPort: 9000},
			},
			want: []string{},
		},
		{
			name: "overlapping source security group sets keep each ID once",
			rules: infrav1.IngressRules{
				rule("a", nil, []string{"sg-1", "sg-2"}),
				rule("b", nil, []string{"sg-2"}),
			},
			want: []string{"sg-1", "sg-2"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			got := dedupeByPermission(expandIngressRules(tc.rules))
			g.Expect(sources(got)).To(Equal(tc.want))
		})
	}

	t.Run("dedupe before expand would miss grouped overlap", func(t *testing.T) {
		g := NewWithT(t)
		rules := infrav1.IngressRules{
			rule("group", []string{"10.0.0.1/32", "10.0.0.2/32"}, nil),
			rule("single", []string{"10.0.0.2/32"}, nil),
		}
		g.Expect(dedupeByPermission(rules)).To(HaveLen(2), "whole-rule keys differ, so only a post-expand dedupe collapses ip2")
		g.Expect(dedupeByPermission(expandIngressRules(rules))).To(HaveLen(2))
		g.Expect(expandIngressRules(dedupeByPermission(rules))).To(HaveLen(3))
	})
}

func TestDescriptionDrift(t *testing.T) {
	rule := func(desc, cidr string) infrav1.IngressRule {
		return infrav1.IngressRule{Description: desc, Protocol: infrav1.SecurityGroupProtocolTCP, FromPort: 6443, ToPort: 6443, CidrBlocks: []string{cidr}}
	}
	tests := []struct {
		name          string
		want, current infrav1.IngressRules
		expected      infrav1.IngressRules
	}{
		{
			name:     "same description is not drift",
			want:     infrav1.IngressRules{rule("a", "10.0.0.0/24")},
			current:  infrav1.IngressRules{rule("a", "10.0.0.0/24")},
			expected: nil,
		},
		{
			name:     "changed description is drift",
			want:     infrav1.IngressRules{rule("new", "10.0.0.0/24")},
			current:  infrav1.IngressRules{rule("old", "10.0.0.0/24")},
			expected: infrav1.IngressRules{rule("new", "10.0.0.0/24")},
		},
		{
			name:     "cleared description is drift",
			want:     infrav1.IngressRules{rule("", "10.0.0.0/24")},
			current:  infrav1.IngressRules{rule("old", "10.0.0.0/24")},
			expected: infrav1.IngressRules{rule("", "10.0.0.0/24")},
		},
		{
			name:     "a permission AWS does not hold yet is not drift",
			want:     infrav1.IngressRules{rule("new", "10.0.0.0/24")},
			current:  infrav1.IngressRules{rule("old", "10.0.1.0/24")},
			expected: nil,
		},
		{
			name:     "non-canonical want matches the masked AWS form",
			want:     infrav1.IngressRules{rule("new", "10.0.0.9/24")},
			current:  infrav1.IngressRules{rule("old", "10.0.0.0/24")},
			expected: infrav1.IngressRules{rule("new", "10.0.0.9/24")},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			NewWithT(t).Expect(descriptionDrift(tc.want, tc.current)).To(Equal(tc.expected))
		})
	}
}

func TestDescriptionDriftEmptyDescriptions(t *testing.T) {
	rule := func(desc string) infrav1.IngressRules {
		return infrav1.IngressRules{{Description: desc, Protocol: infrav1.SecurityGroupProtocolTCP, FromPort: 22, ToPort: 22, CidrBlocks: []string{"10.0.0.0/8"}}}
	}
	// AWS returns no description for a permission created without one and CAPA reads that as "".
	NewWithT(t).Expect(descriptionDrift(rule(""), rule(""))).To(BeEmpty(), "two empty descriptions converge")
	NewWithT(t).Expect(descriptionDrift(rule("added"), rule(""))).To(Equal(rule("added")), "a new description is applied")
	NewWithT(t).Expect(descriptionDrift(rule(""), rule("old"))).To(Equal(rule("")), "a cleared description is applied")
}

// The reconcile compares what CAPA wants with what AWS returns. This feeds every rule through the
// same conversion CAPA does on the way out and back (with the protocol spelled the way EC2 returns it)
// and checks that the identity is stable, otherwise a permission would be revoked and authorized on
// every reconcile.
func TestPermissionKeyRoundTripThroughEC2(t *testing.T) {
	tests := []struct {
		name string
		rule infrav1.IngressRule
	}{
		{"tcp cidr", infrav1.IngressRule{Description: "d", Protocol: infrav1.SecurityGroupProtocolTCP, FromPort: 6443, ToPort: 6443, CidrBlocks: []string{"10.0.0.0/16"}}},
		{"tcp non-canonical cidr", infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolTCP, FromPort: 22, ToPort: 22, CidrBlocks: []string{"10.0.0.7/24"}}},
		{"udp ipv6 with description", infrav1.IngressRule{Description: "v6", Protocol: infrav1.SecurityGroupProtocolUDP, FromPort: 53, ToPort: 53, IPv6CidrBlocks: []string{"2001:DB8::/32"}}},
		{"icmp all codes", infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolICMP, FromPort: -1, ToPort: -1, CidrBlocks: []string{"10.0.0.0/8"}}},
		{"icmp echo", infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolICMP, FromPort: 8, ToPort: 0, CidrBlocks: []string{"10.0.0.0/8"}}},
		{"icmpv6", infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolICMPv6, FromPort: 128, ToPort: -1, IPv6CidrBlocks: []string{"::/0"}}},
		{"ip in ip", infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolIPinIP, FromPort: -1, ToPort: 65535, SourceSecurityGroupIDs: []string{"sg-1"}}},
		{"esp", infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolESP, FromPort: -1, ToPort: -1, SourceSecurityGroupIDs: []string{"sg-1"}}},
		{"all traffic", infrav1.IngressRule{Protocol: infrav1.SecurityGroupProtocolAll, FromPort: -1, ToPort: -1, SourceSecurityGroupIDs: []string{"sg-1"}}},
		{"source group", infrav1.IngressRule{Description: "sg", Protocol: infrav1.SecurityGroupProtocolTCP, FromPort: 2379, ToPort: 2380, SourceSecurityGroupIDs: []string{"sg-2"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			perm := ingressRuleToSDKType(nil, &tc.rule)
			g.Expect(perm).NotTo(BeNil())
			// EC2 spells ICMPv6 as a name on the way back, and reports a source group
			// together with the owning account.
			if aws.ToString(perm.IpProtocol) == string(infrav1.SecurityGroupProtocolICMPv6) {
				perm.IpProtocol = aws.String(IPProtocolICMPv6)
			}
			for i := range perm.UserIdGroupPairs {
				perm.UserIdGroupPairs[i].UserId = aws.String("123456789012")
			}

			observed := ingressRulesFromSDKType(*perm)
			g.Expect(observed).To(HaveLen(1))
			want := expandIngressRules(infrav1.IngressRules{tc.rule})
			g.Expect(want).To(HaveLen(1))
			g.Expect(permissionKey(observed[0])).To(Equal(permissionKey(want[0])))
		})
	}
}
