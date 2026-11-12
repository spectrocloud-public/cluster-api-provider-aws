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

package controllers

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"

	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	bsutil "sigs.k8s.io/cluster-api/bootstrap/util"
)

func TestEKSConfigReconcilerReturnEarlyIfClusterInfraNotReady(t *testing.T) {
	g := NewWithT(t)

	cluster := newCluster("cluster")
	machine := newMachine(cluster, "machine")
	config := newEKSConfig(machine)

	cluster.Status = clusterv1.ClusterStatus{
		Initialization: clusterv1.ClusterInitializationStatus{
			InfrastructureProvisioned: ptr.To(true),
		},
	}

	reconciler := EKSConfigReconciler{
		Client: testEnv.Client,
	}

	g.Eventually(func(gomega Gomega) {
		_, err := reconciler.joinWorker(context.Background(), cluster, config, configOwner("Machine"))
		gomega.Expect(err).NotTo(HaveOccurred())
	}).Should(Succeed())
}

func TestEKSConfigReconcilerReturnEarlyIfClusterControlPlaneNotInitialized(t *testing.T) {
	g := NewWithT(t)

	cluster := newCluster("cluster")
	machine := newMachine(cluster, "machine")
	config := newEKSConfig(machine)

	cluster.Status = clusterv1.ClusterStatus{
		Initialization: clusterv1.ClusterInitializationStatus{
			InfrastructureProvisioned: ptr.To(true),
		},
	}

	reconciler := EKSConfigReconciler{
		Client: testEnv.Client,
	}

	g.Eventually(func(gomega Gomega) {
		_, err := reconciler.joinWorker(context.Background(), cluster, config, configOwner("Machine"))
		gomega.Expect(err).NotTo(HaveOccurred())
	}).Should(Succeed())
}

func configOwner(kind string) *bsutil.ConfigOwner {
	unstructuredOwner := unstructured.Unstructured{
		Object: map[string]interface{}{"kind": kind},
	}
	configOwner := bsutil.ConfigOwner{Unstructured: &unstructuredOwner}
	return &configOwner
}

func TestTransformEndpointForSecretRegion(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		region   string
		want     string
	}{
		{
			name:     "non-secret region is left unchanged",
			endpoint: "https://ABC123.gr7.us-east-1.eks.amazonaws.com",
			region:   "us-east-1",
			want:     "https://ABC123.gr7.us-east-1.eks.amazonaws.com",
		},
		{
			name:     "secret region rewrites the commercial endpoint suffix",
			endpoint: "https://ABC123.gr7.us-east-1.eks.amazonaws.com",
			region:   usIsoBEast1Region,
			want:     "https://ABC123.gr7.us-isob-east-1.eks.sc2s.sgov.gov",
		},
		{
			name:     "secret region leaves an unrelated endpoint unchanged",
			endpoint: "https://ABC123.gr7.eu-west-1.eks.amazonaws.com",
			region:   usIsoBEast1Region,
			want:     "https://ABC123.gr7.eu-west-1.eks.amazonaws.com",
		},
		{
			name:     "empty endpoint is left unchanged",
			endpoint: "",
			region:   usIsoBEast1Region,
			want:     "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(transformEndpointForSecretRegion(tc.endpoint, tc.region)).To(Equal(tc.want))
		})
	}
}
