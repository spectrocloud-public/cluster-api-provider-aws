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
	"fmt"
	"net/netip"
	"sort"
	"strings"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
)

// AWS identifies a security group permission by protocol, port range and
// source. The description is not part of that identity, and AWS rejects an
// authorize call that carries the same permission twice. The helpers below
// compare rules by that identity so descriptions never cause a duplicate
// authorize, a needless revoke, or a rule that AWS already holds to be
// authorized again.
//
// Do not use infrav1.IngressRules.Difference or IngressRule.Equals for
// reconciliation, both compare Description.

// permissionKey returns the identity AWS uses for an ingress permission.
// CIDRs are canonicalized because AWS compares their masked forms. Roles are
// ignored when CIDRs or source security group IDs are present because
// processIngressRulesSGs either ignores them or has already resolved them into
// IDs. A rule without any source gets an empty source list, the caller is
// expected to have run processIngressRulesSGs, which assigns the control plane
// security group.
func permissionKey(i infrav1.IngressRule) string {
	protocol := strings.ToLower(string(i.Protocol))
	ports := fmt.Sprintf("%d-%d", i.FromPort, i.ToPort)
	switch i.Protocol {
	case infrav1.SecurityGroupProtocolAll, infrav1.SecurityGroupProtocolIPinIP, infrav1.SecurityGroupProtocolESP:
		// Ports do not apply to these protocols.
		ports = ""
	}

	sources := make([]string, 0, len(i.CidrBlocks)+len(i.IPv6CidrBlocks)+len(i.SourceSecurityGroupIDs)+len(i.SourceSecurityGroupRoles))
	for _, cidr := range i.CidrBlocks {
		sources = append(sources, "cidr:"+canonicalPermissionCIDR(cidr))
	}
	for _, cidr := range i.IPv6CidrBlocks {
		sources = append(sources, "ipv6:"+canonicalPermissionCIDR(cidr))
	}
	for _, id := range i.SourceSecurityGroupIDs {
		sources = append(sources, "sg:"+id)
	}
	if len(i.SourceSecurityGroupIDs) == 0 && len(i.CidrBlocks) == 0 && len(i.IPv6CidrBlocks) == 0 {
		for _, role := range i.SourceSecurityGroupRoles {
			sources = append(sources, "role:"+string(role))
		}
	}
	sort.Strings(sources)

	return strings.Join([]string{protocol, ports, strings.Join(sources, ",")}, "|")
}

// canonicalPermissionCIDR returns the masked CIDR form AWS uses when it
// compares security group permissions. Invalid values are returned unchanged.
func canonicalPermissionCIDR(cidr string) string {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return cidr
	}
	return prefix.Masked().String()
}

// dedupeByPermission keeps the first rule for each permission identity.
// The reconcile pass must run it after expandIngressRules, because a grouped rule
// and an expanded single-source rule have different whole-rule keys but the same
// per-source one. Run on grouped rules it only removes repeats of a whole rule.
func dedupeByPermission(rules infrav1.IngressRules) infrav1.IngressRules {
	seen := make(map[string]struct{}, len(rules))
	out := make(infrav1.IngressRules, 0, len(rules))
	for index := range rules {
		key := permissionKey(rules[index])
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, rules[index])
	}
	return out
}

// differenceByPermission returns the rules in a whose permission identity is
// absent from b.
func differenceByPermission(a, b infrav1.IngressRules) (out infrav1.IngressRules) {
	keys := make(map[string]struct{}, len(b))
	for index := range b {
		keys[permissionKey(b[index])] = struct{}{}
	}
	for index := range a {
		if _, found := keys[permissionKey(a[index])]; found {
			continue
		}
		out = append(out, a[index])
	}
	return out
}

// descriptionDrift returns the rules in want that already exist in current
// (same permission identity) but carry a different description. The AWS
// permission is identical, so the identity differences never see these. The
// caller revokes and re-authorizes them to change the description.
func descriptionDrift(want, current infrav1.IngressRules) (out infrav1.IngressRules) {
	existing := make(map[string]string, len(current))
	for index := range current {
		existing[permissionKey(current[index])] = current[index].Description
	}
	for index := range want {
		description, found := existing[permissionKey(want[index])]
		if found && description != want[index].Description {
			out = append(out, want[index])
		}
	}
	return out
}
