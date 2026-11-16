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

package controllers

// Spectro fork-only test file (PCP-7927). It covers the upstream cluster-scoped credentials change
// (kubernetes-sigs/cluster-api-provider-aws#6282) end to end, which upstream tests do not.
//
// Runs the real AWSMachineTemplate controller under the shared envtest manager (real API server, CRD
// validation, webhooks, status subresource, watches), with STS and EC2 faked over AWS_ENDPOINT_URL.

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/test/helpers/spectrofakeaws"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
)

// The shared manager is process-wide and controller names must be unique, so register once. The watch filter
// restricts this controller to objects this test labels, so other envtest tests' AWSMachineTemplates are never
// reconciled (and never reach a real AWS endpoint).
var (
	machineTemplateEnvtestOnce sync.Once
	machineTemplateEnvtestErr  error
)

const machineTemplateWatchFilter = "spectro-pcp-7927"

func TestAWSMachineTemplateControllerEnvtestUsesClusterIdentity(t *testing.T) {
	g := NewWithT(t)

	aws := spectrofakeaws.New(t)
	aws.SetControllerCredentials(t)

	machineTemplateEnvtestOnce.Do(func() {
		machineTemplateEnvtestErr = (&AWSMachineTemplateReconciler{
			Client:           testEnv.GetClient(),
			WatchFilterValue: machineTemplateWatchFilter,
		}).SetupWithManager(ctx, testEnv, controller.Options{})
	})
	g.Expect(machineTemplateEnvtestErr).NotTo(HaveOccurred())

	dropRoleIdentityWebhooks(g)

	suffix := rand.String(6)
	ns, err := testEnv.CreateNamespace(ctx, "awsmt-identity-"+suffix)
	g.Expect(err).NotTo(HaveOccurred())

	allowAll := infrav1.AWSClusterIdentitySpec{AllowedNamespaces: &infrav1.AllowedNamespaces{}}
	controllerIdentity := &infrav1.AWSClusterControllerIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: infrav1.AWSClusterControllerIdentityName},
		Spec:       infrav1.AWSClusterControllerIdentitySpec{AWSClusterIdentitySpec: allowAll},
	}
	createdControllerIdentity := true
	if err := testEnv.Create(ctx, controllerIdentity); err != nil {
		g.Expect(client.IgnoreAlreadyExists(err)).To(Succeed())
		createdControllerIdentity = false
	}
	roleIdentity := &infrav1.AWSClusterRoleIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: "customer-role-" + suffix},
		Spec: infrav1.AWSClusterRoleIdentitySpec{
			AWSClusterIdentitySpec: allowAll,
			AWSRoleSpec:            infrav1.AWSRoleSpec{RoleArn: "arn:aws:iam::111122223333:role/customer", SessionName: "s"},
			SourceIdentityRef: &infrav1.AWSIdentityReference{
				Name: infrav1.AWSClusterControllerIdentityName,
				Kind: infrav1.ControllerIdentityKind,
			},
		},
	}
	g.Expect(testEnv.Create(ctx, roleIdentity)).To(Succeed())

	awsCluster := &infrav1.AWSCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "c-" + suffix, Namespace: ns.Name},
		Spec: infrav1.AWSClusterSpec{
			Region:      "us-east-1",
			IdentityRef: &infrav1.AWSIdentityReference{Name: roleIdentity.Name, Kind: infrav1.ClusterRoleIdentityKind},
		},
	}
	g.Expect(testEnv.Create(ctx, awsCluster)).To(Succeed())

	cluster := &clusterv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{Name: awsCluster.Name, Namespace: ns.Name},
		Spec: clusterv1.ClusterSpec{
			InfrastructureRef: clusterv1.ContractVersionedObjectReference{
				APIGroup: infrav1.GroupVersion.Group, Kind: "AWSCluster", Name: awsCluster.Name,
			},
		},
	}
	g.Expect(testEnv.Create(ctx, cluster)).To(Succeed())

	template := &infrav1.AWSMachineTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "t-" + suffix,
			Namespace: ns.Name,
			Labels:    map[string]string{clusterv1.WatchLabel: machineTemplateWatchFilter},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: clusterv1.GroupVersion.String(), Kind: "Cluster", Name: cluster.Name, UID: cluster.UID,
			}},
		},
		Spec: infrav1.AWSMachineTemplateSpec{Template: infrav1.AWSMachineTemplateResource{
			Spec: infrav1.AWSMachineSpec{InstanceType: "t3.large"},
		}},
	}
	g.Expect(testEnv.Create(ctx, template)).To(Succeed())

	t.Cleanup(func() {
		objs := []client.Object{template, cluster, awsCluster, roleIdentity, ns}
		if createdControllerIdentity {
			objs = append(objs, controllerIdentity)
		}
		_ = testEnv.Cleanup(ctx, objs...)
	})

	key := client.ObjectKeyFromObject(template)
	g.Eventually(func(g Gomega) {
		got := &infrav1.AWSMachineTemplate{}
		g.Expect(testEnv.Get(ctx, key, got)).To(Succeed())
		g.Expect(got.Status.Capacity).To(HaveKey(corev1.ResourceCPU), "capacity never populated; EC2 calls: %v", aws.Calls())
		g.Expect(got.Status.NodeInfo).NotTo(BeNil())
		g.Expect(got.Status.NodeInfo.Architecture).To(Equal(infrav1.ArchitectureAmd64))
	}, 30*time.Second, 250*time.Millisecond).Should(Succeed())

	for _, c := range aws.Calls() {
		t.Log(fmt.Sprintf("%s signer=%s", c.Action, c.Signer))
	}
	g.Expect(aws.Assumed()).To(BeTrue(), "identityRef role must be assumed")
	g.Expect(aws.EC2Signers()).NotTo(BeEmpty())
	g.Expect(aws.EC2Signers()).To(HaveEach(Equal(spectrofakeaws.AssumedKey)),
		"EC2 calls must be signed by the assumed role, not the controller")
}

// dropRoleIdentityWebhooks removes the AWSClusterRoleIdentity entries from the webhook configurations.
// config/webhook/manifests.yaml declares them, but the shared suite (suite_test.go) registers no handler for
// that kind, so creating a role identity would otherwise fail with "the server could not find the requested
// resource". Dropping them here keeps the shared suite untouched.
func dropRoleIdentityWebhooks(g Gomega) {
	const marker = "awsclusterroleidentity"

	mutating := &admissionv1.MutatingWebhookConfigurationList{}
	g.Expect(testEnv.List(ctx, mutating)).To(Succeed())
	for i := range mutating.Items {
		cfg := &mutating.Items[i]
		kept := cfg.Webhooks[:0]
		for _, w := range cfg.Webhooks {
			if !strings.Contains(w.Name, marker) {
				kept = append(kept, w)
			}
		}
		if len(kept) != len(cfg.Webhooks) {
			cfg.Webhooks = kept
			g.Expect(testEnv.Update(ctx, cfg)).To(Succeed())
		}
	}

	validating := &admissionv1.ValidatingWebhookConfigurationList{}
	g.Expect(testEnv.List(ctx, validating)).To(Succeed())
	for i := range validating.Items {
		cfg := &validating.Items[i]
		kept := cfg.Webhooks[:0]
		for _, w := range cfg.Webhooks {
			if !strings.Contains(w.Name, marker) {
				kept = append(kept, w)
			}
		}
		if len(kept) != len(cfg.Webhooks) {
			cfg.Webhooks = kept
			g.Expect(testEnv.Update(ctx, cfg)).To(Succeed())
		}
	}
}
