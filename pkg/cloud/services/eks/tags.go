/*
Copyright 2020 The Kubernetes Authors.

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
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/eks/eksiface"
	"github.com/pkg/errors"
	"k8s.io/utils/ptr"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/converters"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/tags"
)

const (
	eksClusterNameTag              = "eks:cluster-name"
	eksNodeGroupNameTag            = "eks:nodegroup-name"
	eksClusterAutoscalerEnabledTag = "k8s.io/cluster-autoscaler/enabled"
)

func (s *Service) reconcileTags(cluster *eks.Cluster) error {
	clusterTags := converters.MapPtrToMap(cluster.Tags)
	buildParams := s.getEKSTagParams(*cluster.Arn)
	tagsBuilder := tags.New(buildParams, tags.WithEKS(s.EKSClient))
	if err := tagsBuilder.Ensure(clusterTags); err != nil {
		return fmt.Errorf("failed ensuring tags on cluster: %w", err)
	}

	return nil
}

func (s *Service) getEKSTagParams(id string) *infrav1.BuildParams {
	name := s.scope.KubernetesClusterName()

	return &infrav1.BuildParams{
		ClusterName: name,
		ResourceID:  id,
		Lifecycle:   infrav1.ResourceLifecycleOwned,
		Name:        aws.String(name),
		Role:        aws.String(infrav1.CommonRoleTagValue),
		Additional:  s.scope.AdditionalTags(),
	}
}

func getTagUpdates(currentTags map[string]string, desiredTags map[string]string) (untagKeys []string, newTags map[string]string) {
	untagKeys = []string{}
	newTags = make(map[string]string)
	for key := range currentTags {
		if _, ok := desiredTags[key]; !ok && !strings.HasPrefix(key, tags.AwsInternalTagPrefix) {
			untagKeys = append(untagKeys, key)
		}
	}
	for key, value := range desiredTags {
		if currentV, ok := currentTags[key]; !ok || value != currentV {
			newTags[key] = value
		}
	}
	return untagKeys, newTags
}

func getASGTagUpdates(clusterName string, currentTags, desiredTags map[string]string) (tagsToDelete, tagsToAdd map[string]string) {
	officialASGTagsByEKS := []string{
		eksClusterNameTag,
		eksNodeGroupNameTag,
		fmt.Sprintf("k8s.io/cluster-autoscaler/%s", clusterName),
		eksClusterAutoscalerEnabledTag,
		infrav1.ClusterAWSCloudProviderTagKey(clusterName),
	}
	tagsToDelete = make(map[string]string)
	tagsToAdd = make(map[string]string)
	for k, v := range currentTags {
		if _, ok := desiredTags[k]; !ok && !slices.Contains(officialASGTagsByEKS, k) {
			tagsToDelete[k] = v
		}
	}
	for key, value := range desiredTags {
		if currentV, ok := currentTags[key]; !ok || value != currentV {
			tagsToAdd[key] = value
		}
	}
	return tagsToDelete, tagsToAdd
}

func (s *NodegroupService) reconcileTags(ng *eks.Nodegroup) error {
	tags := ngTags(s.scope.ClusterName(), s.scope.AdditionalTags())
	return updateTags(s.EKSClient, ng.NodegroupArn, aws.StringValueMap(ng.Tags), tags)
}

func tagDescriptionsToMap(input []*autoscaling.TagDescription) map[string]string {
	tags := make(map[string]string)
	for _, v := range input {
		tags[*v.Key] = *v.Value
	}
	return tags
}

func (s *NodegroupService) reconcileASGTags(ng *eks.Nodegroup) error {
	s.scope.Info("Reconciling ASG tags", "cluster-name", s.scope.ClusterName(), "nodegroup-name", *ng.NodegroupName)
	asg, err := s.describeASGs(ng)
	if err != nil {
		return errors.Wrap(err, "failed to describe ASG for nodegroup")
	}
	if asg == nil {
		s.scope.Debug("ASG not found for nodegroup, skipping tag reconciliation", "nodegroup-name", *ng.NodegroupName)
		return nil
	}

	tagsToDelete, tagsToAdd := getASGTagUpdates(s.scope.ClusterName(), tagDescriptionsToMap(asg.Tags), s.scope.AdditionalTags())
	s.scope.Debug("Tags", "tagsToAdd", tagsToAdd, "tagsToDelete", tagsToDelete)

	if len(tagsToAdd) > 0 {
		input := &autoscaling.CreateOrUpdateTagsInput{}
		for k, v := range tagsToAdd {
			input.Tags = append(input.Tags, &autoscaling.Tag{
				Key:               ptr.To(k),
				PropagateAtLaunch: aws.Bool(true),
				ResourceId:        asg.AutoScalingGroupName,
				ResourceType:      ptr.To("auto-scaling-group"),
				Value:             ptr.To(v),
			})
		}
		_, err = s.AutoscalingClient.CreateOrUpdateTagsWithContext(context.TODO(), input)
		if err != nil {
			return errors.Wrap(err, "failed to add tags to nodegroup's AutoScalingGroup")
		}
	}

	if len(tagsToDelete) > 0 {
		input := &autoscaling.DeleteTagsInput{}
		for k := range tagsToDelete {
			input.Tags = append(input.Tags, &autoscaling.Tag{
				Key:          ptr.To(k),
				ResourceId:   asg.AutoScalingGroupName,
				ResourceType: ptr.To("auto-scaling-group"),
			})
		}
		_, err = s.AutoscalingClient.DeleteTagsWithContext(context.TODO(), input)
		if err != nil {
			return errors.Wrap(err, "failed to delete tags to nodegroup's AutoScalingGroup")
		}
	}

	return nil
}

func (s *FargateService) reconcileTags(fp *eks.FargateProfile) error {
	tags := ngTags(s.scope.ClusterName(), s.scope.AdditionalTags())
	return updateTags(s.EKSClient, fp.FargateProfileArn, aws.StringValueMap(fp.Tags), tags)
}

func updateTags(client eksiface.EKSAPI, arn *string, existingTags, desiredTags map[string]string) error {
	untagKeys, newTags := getTagUpdates(existingTags, desiredTags)

	if len(newTags) > 0 {
		tagInput := &eks.TagResourceInput{
			ResourceArn: arn,
			Tags:        aws.StringMap(newTags),
		}
		_, err := client.TagResource(tagInput)
		if err != nil {
			return err
		}
	}

	if len(untagKeys) > 0 {
		untagInput := &eks.UntagResourceInput{
			ResourceArn: arn,
			TagKeys:     aws.StringSlice(untagKeys),
		}
		_, err := client.UntagResource(untagInput)
		if err != nil {
			return err
		}
	}

	return nil
}
