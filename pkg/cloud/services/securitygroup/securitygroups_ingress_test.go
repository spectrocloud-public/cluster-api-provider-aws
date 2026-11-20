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
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/awserrors"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/scope"
	"sigs.k8s.io/cluster-api-provider-aws/v2/test/mocks"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
)

const kubeletNATCIDR = "10.0.0.10/32"

func apiServerPerm(cidr, description string) types.IpPermission {
	return types.IpPermission{
		IpProtocol: aws.String("tcp"),
		FromPort:   aws.Int32(6443),
		ToPort:     aws.Int32(6443),
		IpRanges:   []types.IpRange{{CidrIp: aws.String(cidr), Description: aws.String(description)}},
	}
}

// apiServerPermIdentity is a permission without a description. AWS matches a revoke that names a
// description only against a rule holding that exact description, so the revoke that swaps a
// description must leave it out, because the new one is never the stored one.
func apiServerPermIdentity(cidr string) types.IpPermission {
	return types.IpPermission{
		IpProtocol: aws.String("tcp"),
		FromPort:   aws.Int32(6443),
		ToPort:     aws.Int32(6443),
		IpRanges:   []types.IpRange{{CidrIp: aws.String(cidr)}},
	}
}

func apiServerRule(cidr, description string) infrav1.IngressRule {
	return infrav1.IngressRule{
		Description: description,
		Protocol:    infrav1.SecurityGroupProtocolTCP,
		FromPort:    infrav1.DefaultAPIServerPort,
		ToPort:      infrav1.DefaultAPIServerPort,
		CidrBlocks:  []string{cidr},
	}
}

// TestReconcileExistingAPIServerLBRules drives the second pass of ReconcileSecurityGroups against an
// apiserver-lb group that already exists, and asserts the exact AWS calls.
func TestReconcileExistingAPIServerLBRules(t *testing.T) {
	apiErr := func(code string) error { return &smithy.GenericAPIError{Code: code, Message: code} }
	kubelet := apiServerPerm(kubeletNATCIDR, "Kubernetes API")

	tests := []struct {
		name     string
		custom   []infrav1.IngressRule
		existing []types.IpPermission
		expect   func(m *mocks.MockEC2APIMockRecorder)
		wantErr  bool
		// reconciles is how many times ReconcileSecurityGroups runs, 1 when unset.
		reconciles int
	}{
		{
			name:     "converged group makes no rule calls",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "office")},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "office")},
		},
		{
			name:     "custom rule repeating the kubelet permission with another description makes no calls",
			custom:   []infrav1.IngressRule{apiServerRule(kubeletNATCIDR, "VPC access")},
			existing: []types.IpPermission{kubelet},
		},
		{
			name:     "non-canonical custom CIDR matches the masked form AWS stores",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.9/24", "office")},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "office")},
		},
		{
			name:     "only the extra rule is revoked",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "office")},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "office"), apiServerPerm("203.0.113.0/24", "stale")},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				m.RevokeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.RevokeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("203.0.113.0/24", "stale")},
				})).Return(&ec2.RevokeSecurityGroupIngressOutput{}, nil)
			},
		},
		{
			name: "duplicate custom rules authorize one permission",
			custom: []infrav1.IngressRule{
				apiServerRule("192.0.2.0/24", "first"),
				apiServerRule("192.0.2.0/24", "second"),
			},
			existing: []types.IpPermission{kubelet},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "first")},
				})).Return(&ec2.AuthorizeSecurityGroupIngressOutput{}, nil)
			},
		},
		{
			name: "grouped custom rule partially overlapping the kubelet rule authorizes only the new sources",
			custom: []infrav1.IngressRule{{
				Description: "mixed",
				Protocol:    infrav1.SecurityGroupProtocolTCP,
				FromPort:    infrav1.DefaultAPIServerPort,
				ToPort:      infrav1.DefaultAPIServerPort,
				CidrBlocks:  []string{kubeletNATCIDR, "192.0.2.0/24"},
			}},
			existing: []types.IpPermission{kubelet},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "mixed")},
				})).Return(&ec2.AuthorizeSecurityGroupIngressOutput{}, nil)
			},
		},
		{
			name:     "description change revokes and re-authorizes the same permission",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "new description")},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "old description")},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				revoke := m.RevokeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.RevokeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPermIdentity("192.0.2.0/24")},
				})).Return(&ec2.RevokeSecurityGroupIngressOutput{}, nil)
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "new description")},
				})).Return(&ec2.AuthorizeSecurityGroupIngressOutput{}, nil).After(revoke)
			},
		},
		{
			name:     "a real change and a description change authorize first, then revoke, then swap the description",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "new description"), apiServerRule("198.51.100.0/24", "added")},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "old description"), apiServerPerm("203.0.113.0/24", "stale")},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				add := m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("198.51.100.0/24", "added")},
				})).Return(&ec2.AuthorizeSecurityGroupIngressOutput{}, nil)
				stale := m.RevokeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.RevokeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("203.0.113.0/24", "stale")},
				})).Return(&ec2.RevokeSecurityGroupIngressOutput{}, nil).After(add)
				drop := m.RevokeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.RevokeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPermIdentity("192.0.2.0/24")},
				})).Return(&ec2.RevokeSecurityGroupIngressOutput{}, nil).After(stale)
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "new description")},
				})).Return(&ec2.AuthorizeSecurityGroupIngressOutput{}, nil).After(drop)
			},
		},
		{
			name:     "authorize failure after a description-only revoke restores the permission",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "new description")},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "old description")},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				revoke := m.RevokeSecurityGroupIngress(context.TODO(), gomock.Any()).Return(&ec2.RevokeSecurityGroupIngressOutput{}, nil)
				failed := m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Any()).Return(nil, apiErr("RequestLimitExceeded")).After(revoke)
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "new description")},
				})).Return(&ec2.AuthorizeSecurityGroupIngressOutput{}, nil).After(failed)
			},
			wantErr: true,
		},
		{
			name:     "a failed authorize leaves the group untouched, nothing is revoked",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "office")},
			existing: []types.IpPermission{kubelet, apiServerPerm("203.0.113.0/24", "stale")},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "office")},
				})).Return(nil, apiErr("RulesPerSecurityGroupLimitExceeded"))
			},
			wantErr: true,
		},
		{
			name:       "a persistently failing authorize never revokes live rules across reconciles",
			custom:     []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "new description"), apiServerRule("198.51.100.0/24", "added")},
			existing:   []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "old description"), apiServerPerm("203.0.113.0/24", "stale")},
			reconciles: 2,
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("198.51.100.0/24", "added")},
				})).Return(nil, apiErr("RequestLimitExceeded")).Times(2)
			},
			wantErr: true,
		},
		{
			name:     "a failed restore still returns the original authorize error",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "new description")},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "old description")},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				revoke := m.RevokeSecurityGroupIngress(context.TODO(), gomock.Any()).Return(&ec2.RevokeSecurityGroupIngressOutput{}, nil)
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Any()).Return(nil, apiErr("RequestLimitExceeded")).Times(2).After(revoke)
			},
			wantErr: true,
		},
		{
			name:     "a description change on a CIDR that is not in masked form revokes by identity with the spec CIDR",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.9/24", "new description")},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "old description")},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				// AWS stores 192.0.2.0/24 and accepts the unmasked spelling on revoke when the
				// description is left out.
				revoke := m.RevokeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.RevokeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPermIdentity("192.0.2.9/24")},
				})).Return(&ec2.RevokeSecurityGroupIngressOutput{}, nil)
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.9/24", "new description")},
				})).Return(&ec2.AuthorizeSecurityGroupIngressOutput{}, nil).After(revoke)
			},
		},
		{
			name: "a failed description swap restores every revoked permission one at a time",
			custom: []infrav1.IngressRule{
				apiServerRule("192.0.2.0/24", "new one"),
				apiServerRule("198.51.100.0/24", "new two"),
			},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "old one"), apiServerPerm("198.51.100.0/24", "old two")},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				revoke := m.RevokeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.RevokeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPermIdentity("192.0.2.0/24"), apiServerPermIdentity("198.51.100.0/24")},
				})).Return(&ec2.RevokeSecurityGroupIngressOutput{}, nil)
				failed := m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "new one"), apiServerPerm("198.51.100.0/24", "new two")},
				})).Return(nil, apiErr("RequestLimitExceeded")).After(revoke)
				first := m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "new one")},
				})).Return(nil, apiErr("RequestLimitExceeded")).After(failed)
				// One throttled restore does not stop the other permission from being put back.
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("198.51.100.0/24", "new two")},
				})).Return(&ec2.AuthorizeSecurityGroupIngressOutput{}, nil).After(first)
			},
			wantErr: true,
		},
		{
			name:     "a drifted permission that is already gone is authorized without error",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "new description")},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "old description")},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				revoke := m.RevokeSecurityGroupIngress(context.TODO(), gomock.Any()).Return(nil, apiErr(awserrors.PermissionNotFound))
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "new description")},
				})).Return(&ec2.AuthorizeSecurityGroupIngressOutput{}, nil).After(revoke)
			},
		},
		{
			name:     "a revoke that fails for a drifted permission is returned and nothing is authorized",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "new description")},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "old description")},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				m.RevokeSecurityGroupIngress(context.TODO(), gomock.Any()).Return(nil, apiErr("RequestLimitExceeded"))
			},
			wantErr: true,
		},
		{
			name: "a non-duplicate error in the one at a time fallback is returned and stops the loop",
			custom: []infrav1.IngressRule{
				apiServerRule("192.0.2.0/24", "a"),
				apiServerRule("198.51.100.0/24", "b"),
			},
			existing: []types.IpPermission{kubelet},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				batch := m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "a"), apiServerPerm("198.51.100.0/24", "b")},
				})).Return(nil, apiErr(awserrors.PermissionDuplicate))
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "a")},
				})).Return(nil, apiErr("RulesPerSecurityGroupLimitExceeded")).After(batch)
			},
			wantErr: true,
		},
		{
			name: "the fallback authorizes what it can and returns the first real error",
			custom: []infrav1.IngressRule{
				apiServerRule("192.0.2.0/24", "a"),
				apiServerRule("198.51.100.0/24", "b"),
			},
			existing: []types.IpPermission{kubelet},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				batch := m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Any()).Return(nil, apiErr(awserrors.PermissionDuplicate))
				first := m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "a")},
				})).Return(&ec2.AuthorizeSecurityGroupIngressOutput{}, nil).After(batch)
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("198.51.100.0/24", "b")},
				})).Return(nil, apiErr("RequestLimitExceeded")).After(first)
			},
			wantErr: true,
		},
		{
			name:     "a single permission that already exists is not an error",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "a")},
			existing: []types.IpPermission{kubelet},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Any()).Return(nil, apiErr(awserrors.PermissionDuplicate)).Times(2)
			},
		},
		{
			name: "a duplicate error on the batch falls back to one permission at a time",
			custom: []infrav1.IngressRule{
				apiServerRule("192.0.2.0/24", "a"),
				apiServerRule("198.51.100.0/24", "b"),
			},
			existing: []types.IpPermission{kubelet},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				batch := m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "a"), apiServerPerm("198.51.100.0/24", "b")},
				})).Return(nil, apiErr(awserrors.PermissionDuplicate))
				first := m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("192.0.2.0/24", "a")},
				})).Return(nil, apiErr(awserrors.PermissionDuplicate)).After(batch)
				m.AuthorizeSecurityGroupIngress(context.TODO(), gomock.Eq(&ec2.AuthorizeSecurityGroupIngressInput{
					GroupId:       aws.String("sg-apiserver-lb"),
					IpPermissions: []types.IpPermission{apiServerPerm("198.51.100.0/24", "b")},
				})).Return(&ec2.AuthorizeSecurityGroupIngressOutput{}, nil).After(first)
			},
		},
		{
			name:     "revoke tolerates a permission that is already gone",
			custom:   []infrav1.IngressRule{apiServerRule("192.0.2.0/24", "office")},
			existing: []types.IpPermission{kubelet, apiServerPerm("192.0.2.0/24", "office"), apiServerPerm("203.0.113.0/24", "stale")},
			expect: func(m *mocks.MockEC2APIMockRecorder) {
				m.RevokeSecurityGroupIngress(context.TODO(), gomock.Any()).Return(nil, apiErr(awserrors.PermissionNotFound))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			ec2Mock := mocks.NewMockEC2API(mockCtrl)

			scheme := runtime.NewScheme()
			_ = infrav1.AddToScheme(scheme)
			awsCluster := &infrav1.AWSCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: infrav1.AWSClusterSpec{
					NetworkSpec: infrav1.NetworkSpec{
						VPC: infrav1.VPCSpec{
							ID:   "vpc-securitygroups",
							Tags: infrav1.Tags{infrav1.ClusterTagKey("test-cluster"): "owned"},
						},
					},
					ControlPlaneLoadBalancer: &infrav1.AWSLoadBalancerSpec{IngressRules: tc.custom},
				},
			}
			awsCluster.Status.Network.NatGatewaysIPs = []string{"10.0.0.10"}

			cs, err := scope.NewClusterScope(scope.ClusterScopeParams{
				Client:     fake.NewClientBuilder().WithScheme(scheme).Build(),
				Cluster:    &clusterv1.Cluster{ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"}},
				AWSCluster: awsCluster,
			})
			g.Expect(err).NotTo(HaveOccurred())

			reconciles := tc.reconciles
			if reconciles == 0 {
				reconciles = 1
			}
			m := ec2Mock.EXPECT()
			m.DescribeSecurityGroups(context.TODO(), gomock.AssignableToTypeOf(&ec2.DescribeSecurityGroupsInput{})).
				Return(&ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{
					Description: aws.String("Kubernetes cluster test-cluster: apiserver-lb"),
					GroupName:   aws.String("test-cluster-apiserver-lb"),
					GroupId:     aws.String("sg-apiserver-lb"),
					Tags: []types.Tag{
						{Key: aws.String("Name"), Value: aws.String("test-cluster-apiserver-lb")},
						{Key: aws.String("sigs.k8s.io/cluster-api-provider-aws/cluster/test-cluster"), Value: aws.String("owned")},
						{Key: aws.String("sigs.k8s.io/cluster-api-provider-aws/role"), Value: aws.String("apiserver-lb")},
					},
					IpPermissions: tc.existing,
				}}}, nil).Times(reconciles)
			if tc.expect != nil {
				tc.expect(m)
			}

			s := NewService(cs, []infrav1.SecurityGroupRole{infrav1.SecurityGroupAPIServerLB})
			s.EC2Client = ec2Mock

			for i := 0; i < reconciles; i++ {
				err = s.ReconcileSecurityGroups()
				if tc.wantErr {
					g.Expect(err).To(HaveOccurred(), "reconcile %d", i+1)
				} else {
					g.Expect(err).NotTo(HaveOccurred(), "reconcile %d", i+1)
				}
			}
		})
	}
}
