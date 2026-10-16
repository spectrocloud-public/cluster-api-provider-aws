/*
Copyright 2025 The Kubernetes Authors.

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

package eks

import (
	"context"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/pkg/errors"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
	ekscontrolplanev1 "sigs.k8s.io/cluster-api-provider-aws/v2/controlplane/eks/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/record"
)

func (s *Service) reconcileAccessEntries(ctx context.Context) error {
	// An empty spec list is not a reason to skip: entries previously created by the
	// controller must still be deleted when the user removes the last one.
	if !accessEntriesEnabled(s.scope.ControlPlane.Spec.AccessConfig) {
		s.scope.Info("access mode is not api or api_and_config_map, skipping reconcile")
		return nil
	}

	existingAccessEntries, err := s.getExistingAccessEntries(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to list existing access entries")
	}

	for _, accessEntry := range s.scope.ControlPlane.Spec.AccessEntries {
		managed, exists := existingAccessEntries[accessEntry.PrincipalARN]
		switch {
		case !exists:
			if err := s.createAccessEntry(ctx, accessEntry); err != nil {
				return errors.Wrapf(err, "failed to create access entry for principal %s", accessEntry.PrincipalARN)
			}
		case managed:
			if err := s.updateAccessEntry(ctx, accessEntry); err != nil {
				return errors.Wrapf(err, "failed to update access entry for principal %s", accessEntry.PrincipalARN)
			}
		default:
			// The entry exists but was not created by this controller, e.g. the cluster creator
			// entry EKS adds when bootstrapClusterCreatorAdminPermissions is true. Only add the
			// requested access policies: recreating it, deleting it or disassociating its policies
			// could remove the controller's own cluster-admin access.
			// Listing such an entry is expected (e.g. to grant the creator extra policies), so only
			// warn when the spec sets fields that are not applied.
			if ignored := unmanagedAccessEntryIgnoredFields(accessEntry); len(ignored) > 0 {
				record.Warnf(s.scope.ControlPlane, "AccessEntryNotManaged", "Access entry for principal %s is not managed by the controller: %s not applied, only access policies are associated", accessEntry.PrincipalARN, strings.Join(ignored, ", "))
			} else {
				s.scope.Debug("Access entry not managed by the controller, only associating access policies", "principalARN", accessEntry.PrincipalARN)
			}
			if err := s.associateAccessPolicies(ctx, accessEntry); err != nil {
				return errors.Wrapf(err, "failed to associate access policies for unmanaged principal %s", accessEntry.PrincipalARN)
			}
		}
		delete(existingAccessEntries, accessEntry.PrincipalARN)
	}

	for principalArn, managed := range existingAccessEntries {
		if !managed {
			continue
		}
		if err := s.deleteAccessEntry(ctx, principalArn); err != nil {
			return errors.Wrapf(err, "failed to delete access entry for principal %s", principalArn)
		}
	}

	record.Event(s.scope.ControlPlane, "SuccessfulReconcileAccessEntries", "Reconciled access entries")
	return nil
}

// unmanagedAccessEntryIgnoredFields returns the spec fields of an access entry that are not
// applied when the entry exists in EKS but is not managed by the controller.
func unmanagedAccessEntryIgnoredFields(accessEntry ekscontrolplanev1.AccessEntry) []string {
	var ignored []string
	if accessEntry.Type != "" && !strings.EqualFold(string(accessEntry.Type), string(ekscontrolplanev1.AccessEntryTypeStandard)) {
		ignored = append(ignored, "type")
	}
	if accessEntry.Username != "" {
		ignored = append(ignored, "username")
	}
	if len(accessEntry.KubernetesGroups) > 0 {
		ignored = append(ignored, "kubernetesGroups")
	}
	return ignored
}

// accessEntriesEnabled returns true when the authentication mode allows access entries.
func accessEntriesEnabled(accessConfig *ekscontrolplanev1.AccessConfig) bool {
	if accessConfig == nil {
		return false
	}
	return accessConfig.AuthenticationMode == ekscontrolplanev1.EKSAuthenticationModeAPI ||
		accessConfig.AuthenticationMode == ekscontrolplanev1.EKSAuthenticationModeAPIAndConfigMap
}

// getExistingAccessEntries returns every access entry of the cluster keyed by principal ARN.
// The value is true when the entry carries the controller's ownership tag.
func (s *Service) getExistingAccessEntries(ctx context.Context) (map[string]bool, error) {
	existingAccessEntries := make(map[string]bool)
	var nextToken *string

	clusterName := s.scope.KubernetesClusterName()
	managedTag := infrav1.ClusterAWSCloudProviderTagKey(s.scope.Name())

	for {
		input := &eks.ListAccessEntriesInput{
			ClusterName: &clusterName,
			NextToken:   nextToken,
		}

		output, err := s.EKSClient.ListAccessEntries(ctx, input)
		if err != nil {
			return nil, errors.Wrap(err, "failed to list access entries")
		}

		for _, principalArn := range output.AccessEntries {
			describeOutput, err := s.EKSClient.DescribeAccessEntry(ctx, &eks.DescribeAccessEntryInput{
				ClusterName:  &clusterName,
				PrincipalArn: &principalArn,
			})
			if err != nil {
				// Skipping the entry would make a managed entry look unmanaged, so it would be
				// neither updated nor deleted. Fail and retry on the next reconcile instead.
				return nil, errors.Wrapf(err, "failed to describe access entry for principal %s", principalArn)
			}

			_, managed := describeOutput.AccessEntry.Tags[managedTag]
			existingAccessEntries[principalArn] = managed
		}

		if output.NextToken == nil {
			break
		}

		nextToken = output.NextToken
	}

	return existingAccessEntries, nil
}

func (s *Service) createAccessEntry(ctx context.Context, accessEntry ekscontrolplanev1.AccessEntry) error {
	clusterName := s.scope.KubernetesClusterName()

	additionalTags := s.scope.AdditionalTags()
	additionalTags[infrav1.ClusterAWSCloudProviderTagKey(s.scope.Name())] = string(infrav1.ResourceLifecycleOwned)
	tags := make(map[string]string)
	for k, v := range additionalTags {
		tags[k] = v
	}

	createInput := &eks.CreateAccessEntryInput{
		ClusterName:  &clusterName,
		PrincipalArn: &accessEntry.PrincipalARN,
		Tags:         tags,
	}

	if len(accessEntry.KubernetesGroups) > 0 {
		createInput.KubernetesGroups = accessEntry.KubernetesGroups
	}

	if accessEntry.Type != "" {
		createInput.Type = accessEntry.Type.APIValue()
	}

	if accessEntry.Username != "" {
		createInput.Username = &accessEntry.Username
	}

	if _, err := s.EKSClient.CreateAccessEntry(ctx, createInput); err != nil {
		return errors.Wrapf(err, "failed to create access entry for principal %s", accessEntry.PrincipalARN)
	}

	if err := s.reconcileAccessPolicies(ctx, accessEntry); err != nil {
		return errors.Wrapf(err, "failed to reconcile access policies for principal %s", accessEntry.PrincipalARN)
	}

	return nil
}

func (s *Service) updateAccessEntry(ctx context.Context, accessEntry ekscontrolplanev1.AccessEntry) error {
	clusterName := s.scope.KubernetesClusterName()
	describeInput := &eks.DescribeAccessEntryInput{
		ClusterName:  &clusterName,
		PrincipalArn: &accessEntry.PrincipalARN,
	}

	describeOutput, err := s.EKSClient.DescribeAccessEntry(ctx, describeInput)
	if err != nil {
		return errors.Wrapf(err, "failed to describe access entry for principal %s", accessEntry.PrincipalARN)
	}

	// Normalize empty spec Type to STANDARD to match what EKS reports for a
	// default STANDARD entry, so an unset Type is not seen as drift.
	desiredType := accessEntry.Type
	if desiredType == "" {
		desiredType = ekscontrolplanev1.AccessEntryTypeStandard
	}

	// Type is the only immutable field, so it is the only one requiring a recreate.
	// UpdateAccessEntry accepts username and Kubernetes groups.
	if *desiredType.APIValue() != aws.ToString(describeOutput.AccessEntry.Type) {
		if err = s.deleteAccessEntry(ctx, accessEntry.PrincipalARN); err != nil {
			return errors.Wrapf(err, "failed to delete access entry for principal %s during recreation", accessEntry.PrincipalARN)
		}

		if err = s.createAccessEntry(ctx, accessEntry); err != nil {
			return errors.Wrapf(err, "failed to recreate access entry for principal %s", accessEntry.PrincipalARN)
		}
		return nil
	}

	slices.Sort(accessEntry.KubernetesGroups)
	slices.Sort(describeOutput.AccessEntry.KubernetesGroups)

	updateInput := &eks.UpdateAccessEntryInput{
		ClusterName:  &clusterName,
		PrincipalArn: &accessEntry.PrincipalARN,
	}
	needsUpdate := false

	if !slices.Equal(accessEntry.KubernetesGroups, describeOutput.AccessEntry.KubernetesGroups) {
		updateInput.KubernetesGroups = accessEntry.KubernetesGroups
		needsUpdate = true
	}

	// An unset username means EKS generates one, so the generated value is not drift.
	existingUsername := ""
	if describeOutput.AccessEntry.Username != nil {
		existingUsername = *describeOutput.AccessEntry.Username
	}

	if accessEntry.Username != "" && accessEntry.Username != existingUsername {
		updateInput.Username = &accessEntry.Username
		needsUpdate = true
	}

	if needsUpdate {
		if _, err := s.EKSClient.UpdateAccessEntry(ctx, updateInput); err != nil {
			return errors.Wrapf(err, "failed to update access entry for principal %s", accessEntry.PrincipalARN)
		}
	}

	if err := s.reconcileAccessPolicies(ctx, accessEntry); err != nil {
		return errors.Wrapf(err, "failed to reconcile access policies for principal %s", accessEntry.PrincipalARN)
	}

	return nil
}

func (s *Service) deleteAccessEntry(ctx context.Context, principalArn string) error {
	clusterName := s.scope.KubernetesClusterName()

	if _, err := s.EKSClient.DeleteAccessEntry(ctx, &eks.DeleteAccessEntryInput{
		ClusterName:  &clusterName,
		PrincipalArn: &principalArn,
	}); err != nil {
		return errors.Wrapf(err, "failed to delete access entry for principal %s", principalArn)
	}

	return nil
}

func (s *Service) reconcileAccessPolicies(ctx context.Context, accessEntry ekscontrolplanev1.AccessEntry) error {
	if !supportsAccessPolicies(accessEntry.Type) {
		s.scope.Info("Skipping access policy reconciliation for non-standard access entry type", "principalARN", accessEntry.PrincipalARN, "type", accessEntry.Type)
		return nil
	}

	existingPolicies, err := s.getExistingAccessPolicies(ctx, accessEntry.PrincipalARN)
	if err != nil {
		return errors.Wrapf(err, "failed to get existing access policies for principal %s", accessEntry.PrincipalARN)
	}

	if err := s.associateMissingAccessPolicies(ctx, accessEntry, existingPolicies); err != nil {
		return err
	}

	for _, policy := range accessEntry.AccessPolicies {
		delete(existingPolicies, policy.PolicyARN)
	}

	clusterName := s.scope.KubernetesClusterName()
	for policyARN := range existingPolicies {
		if _, err := s.EKSClient.DisassociateAccessPolicy(ctx, &eks.DisassociateAccessPolicyInput{
			ClusterName:  &clusterName,
			PrincipalArn: &accessEntry.PrincipalARN,
			PolicyArn:    &policyARN,
		}); err != nil {
			return errors.Wrapf(err, "failed to disassociate access policy %s", policyARN)
		}
	}

	return nil
}

// associateAccessPolicies only adds the access policies of the spec to an access entry; it never
// disassociates existing ones. It is used for access entries not managed by the controller.
func (s *Service) associateAccessPolicies(ctx context.Context, accessEntry ekscontrolplanev1.AccessEntry) error {
	if !supportsAccessPolicies(accessEntry.Type) || len(accessEntry.AccessPolicies) == 0 {
		return nil
	}

	existingPolicies, err := s.getExistingAccessPolicies(ctx, accessEntry.PrincipalARN)
	if err != nil {
		return errors.Wrapf(err, "failed to get existing access policies for principal %s", accessEntry.PrincipalARN)
	}

	return s.associateMissingAccessPolicies(ctx, accessEntry, existingPolicies)
}

// associateMissingAccessPolicies associates the policies of the access entry that are not yet
// associated, or whose access scope differs from the associated one. Unchanged policies are
// skipped to avoid an AWS call per policy on every reconcile.
func (s *Service) associateMissingAccessPolicies(ctx context.Context, accessEntry ekscontrolplanev1.AccessEntry, existingPolicies map[string]ekstypes.AssociatedAccessPolicy) error {
	clusterName := s.scope.KubernetesClusterName()

	for _, policy := range accessEntry.AccessPolicies {
		if existing, ok := existingPolicies[policy.PolicyARN]; ok && accessScopeEqual(existing.AccessScope, policy.AccessScope) {
			continue
		}

		input := &eks.AssociateAccessPolicyInput{
			ClusterName:  &clusterName,
			PrincipalArn: &accessEntry.PrincipalARN,
			PolicyArn:    &policy.PolicyARN,
			AccessScope: &ekstypes.AccessScope{
				Type: ekstypes.AccessScopeType(policy.AccessScope.Type),
			},
		}

		if policy.AccessScope.Type == ekscontrolplanev1.AccessScopeTypeNamespace && len(policy.AccessScope.Namespaces) > 0 {
			input.AccessScope.Namespaces = policy.AccessScope.Namespaces
		}

		if _, err := s.EKSClient.AssociateAccessPolicy(ctx, input); err != nil {
			return errors.Wrapf(err, "failed to associate access policy %s", policy.PolicyARN)
		}
	}

	return nil
}

// supportsAccessPolicies returns true when access policies can be associated with the access
// entry type. EKS only allows access policies on standard access entries.
func supportsAccessPolicies(entryType ekscontrolplanev1.AccessEntryType) bool {
	return entryType == "" || strings.EqualFold(string(entryType), string(ekscontrolplanev1.AccessEntryTypeStandard))
}

// accessScopeEqual compares the access scope associated in EKS with the desired one.
// The EKS scope type is upper case and namespaces are compared ignoring order.
func accessScopeEqual(existing *ekstypes.AccessScope, desired ekscontrolplanev1.AccessScope) bool {
	if existing == nil {
		return false
	}
	if !strings.EqualFold(string(existing.Type), string(desired.Type)) {
		return false
	}
	if desired.Type != ekscontrolplanev1.AccessScopeTypeNamespace {
		return true
	}

	existingNamespaces := slices.Clone(existing.Namespaces)
	desiredNamespaces := slices.Clone(desired.Namespaces)
	slices.Sort(existingNamespaces)
	slices.Sort(desiredNamespaces)
	return slices.Equal(existingNamespaces, desiredNamespaces)
}

func (s *Service) getExistingAccessPolicies(ctx context.Context, principalARN string) (map[string]ekstypes.AssociatedAccessPolicy, error) {
	existingPolicies := map[string]ekstypes.AssociatedAccessPolicy{}
	var nextToken *string
	clusterName := s.scope.KubernetesClusterName()

	for {
		input := &eks.ListAssociatedAccessPoliciesInput{
			ClusterName:  &clusterName,
			PrincipalArn: &principalARN,
			NextToken:    nextToken,
		}

		output, err := s.EKSClient.ListAssociatedAccessPolicies(ctx, input)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list associated access policies for principal %s", principalARN)
		}

		for _, policy := range output.AssociatedAccessPolicies {
			existingPolicies[*policy.PolicyArn] = policy
		}

		if output.NextToken == nil {
			break
		}

		nextToken = output.NextToken
	}

	return existingPolicies, nil
}
