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

// Package controllers provides a way to reconcile EKSConfig objects.
package controllers

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	eksbootstrapv1 "sigs.k8s.io/cluster-api-provider-aws/v2/bootstrap/eks/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/bootstrap/eks/internal/userdata"
	ekscontrolplanev1 "sigs.k8s.io/cluster-api-provider-aws/v2/controlplane/eks/api/v1beta2"
	expinfrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/exp/api/v1beta2"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/logger"
	"sigs.k8s.io/cluster-api-provider-aws/v2/util/paused"
	clusterv1beta1 "sigs.k8s.io/cluster-api/api/core/v1beta1"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	bsutil "sigs.k8s.io/cluster-api/bootstrap/util"
	"sigs.k8s.io/cluster-api/feature"
	"sigs.k8s.io/cluster-api/util"
	v1beta1conditions "sigs.k8s.io/cluster-api/util/deprecated/v1beta1/conditions"
	v1beta1patch "sigs.k8s.io/cluster-api/util/deprecated/v1beta1/patch"
	kubeconfigutil "sigs.k8s.io/cluster-api/util/kubeconfig"
	"sigs.k8s.io/cluster-api/util/predicates"
)

const eksConfigKind = "EKSConfig"

// NodeTypeAL2023 selects nodeadm userdata instead of the AL2 bootstrap script.
const NodeTypeAL2023 = "al2023"

// usIsoBEast1Region is the AWS Secret region whose emulated API server endpoint the
// Sequoia emulator serves.
const usIsoBEast1Region = "us-isob-east-1"

// EKSConfigReconciler reconciles a EKSConfig object.
type EKSConfigReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	WatchFilterValue string
}

// +kubebuilder:rbac:groups=bootstrap.cluster.x-k8s.io,resources=eksconfigs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=bootstrap.cluster.x-k8s.io,resources=eksconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=controlplane.cluster.x-k8s.io,resources=awsmanagedcontrolplanes,verbs=get;list;watch
// +kubebuilder:rbac:groups=cluster.x-k8s.io,resources=machines;machinepools;clusters,verbs=get;list;watch
// +kubebuilder:rbac:groups=cluster.x-k8s.io,resources=machinepools,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete;

func (r *EKSConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, rerr error) {
	log := logger.FromContext(ctx)

	// get EKSConfig
	config := &eksbootstrapv1.EKSConfig{}
	if err := r.Client.Get(ctx, req.NamespacedName, config); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get config")
		return ctrl.Result{}, err
	}
	log = log.WithValues(eksConfigKind, config.GetName())

	// check owner references and look up owning Machine object
	configOwner, err := bsutil.GetTypedConfigOwner(ctx, r.Client, config)
	if apierrors.IsNotFound(err) {
		// no error here, requeue until we find an owner
		log.Debug("eksconfig failed to look up owner reference, re-queueing")
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	if err != nil {
		log.Error(err, "eksconfig failed to get owner")
		return ctrl.Result{}, err
	}
	if configOwner == nil {
		// no error, requeue until we find an owner
		log.Debug("eksconfig has no owner reference set, re-queueing")
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	log = log.WithValues(configOwner.GetKind(), configOwner.GetName())

	cluster, err := util.GetClusterByName(ctx, r.Client, configOwner.GetNamespace(), configOwner.ClusterName())
	if err != nil {
		if errors.Is(err, util.ErrNoCluster) {
			log.Info("EKSConfig does not belong to a cluster yet, re-queuing until it's part of a cluster")
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
		if apierrors.IsNotFound(err) {
			log.Info("Cluster does not exist yet, re-queueing until it is created")
			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
		log.Error(err, "Could not get cluster with metadata")
		return ctrl.Result{}, err
	}
	log = log.WithValues("cluster", klog.KObj(cluster))

	if isPaused, conditionChanged, err := paused.EnsurePausedCondition(ctx, r.Client, cluster, config); err != nil || isPaused || conditionChanged {
		return ctrl.Result{}, err
	}

	patchHelper, err := v1beta1patch.NewHelper(config, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	// set up defer block for updating config
	defer func() {
		v1beta1conditions.SetSummary(config,
			v1beta1conditions.WithConditions(
				eksbootstrapv1.DataSecretAvailableCondition,
			),
			v1beta1conditions.WithStepCounter(),
		)

		patchOpts := []v1beta1patch.Option{}
		if rerr == nil {
			patchOpts = append(patchOpts, v1beta1patch.WithStatusObservedGeneration{})
		}
		if err := patchHelper.Patch(ctx, config, patchOpts...); err != nil {
			log.Error(rerr, "Failed to patch config")
			if rerr == nil {
				rerr = err
			}
		}
	}()

	return r.joinWorker(ctx, cluster, config, configOwner)
}

func (r *EKSConfigReconciler) joinWorker(ctx context.Context, cluster *clusterv1.Cluster, config *eksbootstrapv1.EKSConfig, configOwner *bsutil.ConfigOwner) (ctrl.Result, error) {
	log := logger.FromContext(ctx)

	// only need to reconcile the secret for Machine kinds once, but MachinePools need updates for new launch templates
	if config.Status.DataSecretName != nil && configOwner.GetKind() == "Machine" {
		secretKey := client.ObjectKey{Namespace: config.Namespace, Name: *config.Status.DataSecretName}
		log = log.WithValues("data-secret-name", secretKey.Name)
		existingSecret := &corev1.Secret{}

		// No error here means the Secret exists and we have no
		// reason to proceed.
		err := r.Client.Get(ctx, secretKey, existingSecret)
		switch {
		case err == nil:
			return ctrl.Result{}, nil
		case !apierrors.IsNotFound(err):
			log.Error(err, "unable to check for existing bootstrap secret")
			return ctrl.Result{}, err
		}
	}

	if !cluster.Spec.ControlPlaneRef.IsDefined() || cluster.Spec.ControlPlaneRef.Kind != "AWSManagedControlPlane" {
		return ctrl.Result{}, errors.New("Cluster's controlPlaneRef needs to be an AWSManagedControlPlane in order to use the EKS bootstrap provider")
	}

	if !ptr.Deref(cluster.Status.Initialization.InfrastructureProvisioned, false) {
		log.Info("Cluster infrastructure is not ready")
		v1beta1conditions.MarkFalse(config,
			eksbootstrapv1.DataSecretAvailableCondition,
			eksbootstrapv1.WaitingForClusterInfrastructureReason,
			clusterv1beta1.ConditionSeverityInfo, "")
		return ctrl.Result{}, nil
	}

	if !ptr.Deref(cluster.Status.Initialization.ControlPlaneInitialized, false) {
		log.Info("Control Plane has not yet been initialized")
		v1beta1conditions.MarkFalse(config, eksbootstrapv1.DataSecretAvailableCondition, eksbootstrapv1.WaitingForControlPlaneInitializationReason, clusterv1beta1.ConditionSeverityInfo, "")
		// AL2023 reads the cluster CA from the kubeconfig secret, so it must retry rather
		// than wait for an event: this controller does not watch the control plane.
		if config.Spec.NodeType == NodeTypeAL2023 {
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		return ctrl.Result{}, nil
	}

	controlPlane := &ekscontrolplanev1.AWSManagedControlPlane{}
	if err := r.Get(ctx, client.ObjectKey{Name: cluster.Spec.ControlPlaneRef.Name, Namespace: cluster.Namespace}, controlPlane); err != nil {
		return ctrl.Result{}, err
	}

	if config.Spec.NodeType == NodeTypeAL2023 && !controlPlane.Status.Ready {
		log.Info("Control plane is not ready yet, waiting to generate AL2023 userdata")
		v1beta1conditions.MarkFalse(config, eksbootstrapv1.DataSecretAvailableCondition,
			eksbootstrapv1.DataSecretGenerationFailedReason,
			clusterv1beta1.ConditionSeverityInfo, "Control plane is not ready yet")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	log.Info("Generating userdata")
	fileResolver := FileResolver{Client: r.Client}
	files, err := fileResolver.ResolveFiles(ctx, config.Namespace, config.Spec.Files)
	if err != nil {
		log.Info("Failed to resolve files for user data")
		v1beta1conditions.MarkFalse(config, eksbootstrapv1.DataSecretAvailableCondition, eksbootstrapv1.DataSecretGenerationFailedReason, clusterv1beta1.ConditionSeverityWarning, "%s", err.Error())
		return ctrl.Result{}, err
	}

	// AL2023 renders nodeadm config; the file/user/NTP/mount sections of the spec are not
	// part of that format and are ignored, as they were before the nodeadm split.
	if config.Spec.NodeType == NodeTypeAL2023 {
		return r.joinAL2023Worker(ctx, cluster, config, configOwner, controlPlane)
	}

	nodeInput := &userdata.NodeInput{
		// AWSManagedControlPlane webhooks default and validate EKSClusterName
		ClusterName:              controlPlane.Spec.EKSClusterName,
		KubeletExtraArgs:         config.Spec.KubeletExtraArgs,
		ContainerRuntime:         config.Spec.ContainerRuntime,
		DNSClusterIP:             config.Spec.DNSClusterIP,
		DockerConfigJSON:         config.Spec.DockerConfigJSON,
		APIRetryAttempts:         config.Spec.APIRetryAttempts,
		UseMaxPods:               config.Spec.UseMaxPods,
		PreBootstrapCommands:     config.Spec.PreBootstrapCommands,
		PostBootstrapCommands:    config.Spec.PostBootstrapCommands,
		BootstrapCommandOverride: config.Spec.BootstrapCommandOverride,
		NTP:                      config.Spec.NTP,
		Users:                    config.Spec.Users,
		DiskSetup:                config.Spec.DiskSetup,
		Mounts:                   config.Spec.Mounts,
		Files:                    files,
	}
	if config.Spec.PauseContainer != nil {
		nodeInput.PauseContainerAccount = &config.Spec.PauseContainer.AccountNumber
		nodeInput.PauseContainerVersion = &config.Spec.PauseContainer.Version
	}

	// Check if IPv6 was provided to the user configuration first
	// If not, we also check if the cluster is ipv6 based.
	if config.Spec.ServiceIPV6Cidr != nil && *config.Spec.ServiceIPV6Cidr != "" {
		nodeInput.ServiceIPV6Cidr = config.Spec.ServiceIPV6Cidr
		nodeInput.IPFamily = ptr.To[string]("ipv6")
	}

	// we don't want to override any manually set configuration options.
	if config.Spec.ServiceIPV6Cidr == nil && controlPlane.Spec.NetworkSpec.VPC.IsIPv6Enabled() {
		log.Info("Adding ipv6 data to userdata....")
		nodeInput.ServiceIPV6Cidr = ptr.To[string](controlPlane.Spec.NetworkSpec.VPC.IPv6.CidrBlock)
		nodeInput.IPFamily = ptr.To[string]("ipv6")
	}

	// generate userdata
	userDataScript, err := userdata.NewNode(nodeInput)
	if err != nil {
		log.Error(err, "Failed to create a worker join configuration")
		v1beta1conditions.MarkFalse(config, eksbootstrapv1.DataSecretAvailableCondition, eksbootstrapv1.DataSecretGenerationFailedReason, clusterv1beta1.ConditionSeverityWarning, "")
		return ctrl.Result{}, err
	}

	// store userdata as secret
	if err := r.storeBootstrapData(ctx, cluster, config, userDataScript); err != nil {
		log.Error(err, "Failed to store bootstrap data")
		v1beta1conditions.MarkFalse(config, eksbootstrapv1.DataSecretAvailableCondition, eksbootstrapv1.DataSecretGenerationFailedReason, clusterv1beta1.ConditionSeverityWarning, "")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// joinAL2023Worker generates and stores nodeadm userdata for an AL2023 worker pool.
func (r *EKSConfigReconciler) joinAL2023Worker(ctx context.Context, cluster *clusterv1.Cluster, config *eksbootstrapv1.EKSConfig, configOwner *bsutil.ConfigOwner, controlPlane *ekscontrolplanev1.AWSManagedControlPlane) (ctrl.Result, error) {
	log := logger.FromContext(ctx)

	caCert, err := r.extractCAFromSecret(ctx, client.ObjectKey{Namespace: cluster.Namespace, Name: cluster.Name})
	if err != nil {
		log.Error(err, "Failed to extract CA from kubeconfig secret")
		v1beta1conditions.MarkFalse(config, eksbootstrapv1.DataSecretAvailableCondition,
			eksbootstrapv1.DataSecretGenerationFailedReason,
			clusterv1beta1.ConditionSeverityWarning,
			"Failed to extract CA from kubeconfig secret: %v", err)
		return ctrl.Result{}, err
	}

	// Check if this is a Sequoia emulator environment by reading the CAPA credentials secret.
	isEmulator := false
	capaSecret := &corev1.Secret{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: cluster.Namespace, Name: "capa-manager-bootstrap-credentials"}, capaSecret); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Info("Error getting CAPA credentials secret", "error", err)
		}
	} else if string(capaSecret.Data["sequoia-emulator"]) == "true" {
		isEmulator = true
	}

	apiServerEndpoint := controlPlane.Spec.ControlPlaneEndpoint.Host
	// Emulator only: transform commercial endpoint to Secret region endpoint
	if isEmulator {
		transformed := transformEndpointForSecretRegion(apiServerEndpoint, controlPlane.Spec.Region)
		if transformed != apiServerEndpoint {
			log.Info("Transformed AL2023 API Server Endpoint for emulated Secret region",
				"original", apiServerEndpoint,
				"transformed", transformed,
				"region", controlPlane.Spec.Region)
			apiServerEndpoint = transformed
		}
	}

	al2023Input := &userdata.AL2023Input{
		// AWSManagedControlPlane webhooks default and validate EKSClusterName
		ClusterName:           controlPlane.Spec.EKSClusterName,
		KubeletExtraArgs:      config.Spec.KubeletExtraArgs,
		PreBootstrapCommands:  config.Spec.PreBootstrapCommands,
		PostBootstrapCommands: config.Spec.PostBootstrapCommands,
		DNSClusterIP:          config.Spec.DNSClusterIP,
		UseMaxPods:            config.Spec.UseMaxPods,
		APIServerEndpoint:     apiServerEndpoint,
		CACert:                caCert,
		NodeGroupName:         config.Name,
		ClusterCIDR:           r.getClusterCidr(cluster, controlPlane),
	}

	// A pool that owns its launch template carries the AMI and capacity type used for the
	// node labels; a MachinePool-owned config leaves them unset.
	if configOwner.GetKind() == "AWSManagedMachinePool" {
		pool := &expinfrav1.AWSManagedMachinePool{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: config.Namespace, Name: configOwner.GetName()}, pool); err != nil {
			log.Info("Failed to get AWSManagedMachinePool", "error", err)
		} else {
			if pool.Spec.AWSLaunchTemplate != nil && pool.Spec.AWSLaunchTemplate.AMI.ID != nil {
				al2023Input.AMIImageID = *pool.Spec.AWSLaunchTemplate.AMI.ID
			}
			al2023Input.CapacityType = pool.Spec.CapacityType
		}
	}

	userDataScript, err := userdata.NewAL2023Node(al2023Input)
	if err != nil {
		log.Error(err, "Failed to create a worker join configuration")
		v1beta1conditions.MarkFalse(config, eksbootstrapv1.DataSecretAvailableCondition, eksbootstrapv1.DataSecretGenerationFailedReason, clusterv1beta1.ConditionSeverityWarning, "")
		return ctrl.Result{}, err
	}

	if err := r.storeBootstrapData(ctx, cluster, config, userDataScript); err != nil {
		log.Error(err, "Failed to store bootstrap data")
		v1beta1conditions.MarkFalse(config, eksbootstrapv1.DataSecretAvailableCondition, eksbootstrapv1.DataSecretGenerationFailedReason, clusterv1beta1.ConditionSeverityWarning, "")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// getClusterCidr returns the service CIDR to advertise to nodeadm, preferring the
// cluster's service CIDR and falling back to the control plane VPC CIDR.
func (r *EKSConfigReconciler) getClusterCidr(cluster *clusterv1.Cluster, controlPlane *ekscontrolplanev1.AWSManagedControlPlane) string {
	// v1beta2 made ClusterNetwork and Services value types, so only the slice needs checking.
	if len(cluster.Spec.ClusterNetwork.Services.CIDRBlocks) > 0 {
		return cluster.Spec.ClusterNetwork.Services.CIDRBlocks[0]
	}

	return controlPlane.Spec.NetworkSpec.VPC.CidrBlock
}

// extractCAFromSecret returns the base64 cluster CA from the cluster's kubeconfig secret.
func (r *EKSConfigReconciler) extractCAFromSecret(ctx context.Context, obj client.ObjectKey) (string, error) {
	data, err := kubeconfigutil.FromSecret(ctx, r.Client, obj)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get kubeconfig secret %s", obj.Name)
	}
	config, err := clientcmd.Load(data)
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse kubeconfig data from secret %s", obj.Name)
	}

	for _, cluster := range config.Clusters {
		if len(cluster.CertificateAuthorityData) > 0 {
			return base64.StdEncoding.EncodeToString(cluster.CertificateAuthorityData), nil
		}
	}

	return "", fmt.Errorf("no cluster with CA data found in kubeconfig")
}

func (r *EKSConfigReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, option controller.Options) error {
	b := ctrl.NewControllerManagedBy(mgr).
		For(&eksbootstrapv1.EKSConfig{}).
		WithOptions(option).
		WithEventFilter(predicates.ResourceHasFilterLabel(mgr.GetScheme(), logger.FromContext(ctx).GetLogger(), r.WatchFilterValue)).
		Watches(
			&clusterv1.Machine{},
			handler.EnqueueRequestsFromMapFunc(r.MachineToBootstrapMapFunc),
		)

	if feature.Gates.Enabled(feature.MachinePool) {
		b = b.Watches(
			&clusterv1.MachinePool{},
			handler.EnqueueRequestsFromMapFunc(r.MachinePoolToBootstrapMapFunc),
		)
	}

	c, err := b.Build(r)
	if err != nil {
		return errors.Wrap(err, "failed setting up with a controller manager")
	}

	err = c.Watch(
		source.Kind[client.Object](mgr.GetCache(), &clusterv1.Cluster{},
			handler.EnqueueRequestsFromMapFunc((r.ClusterToEKSConfigs)),
			predicates.ClusterPausedTransitionsOrInfrastructureProvisioned(mgr.GetScheme(), logger.FromContext(ctx).GetLogger())),
	)
	if err != nil {
		return errors.Wrap(err, "failed adding watch for Clusters to controller manager")
	}

	return nil
}

// storeBootstrapData creates a new secret with the data passed in as input,
// sets the reference in the configuration status and ready to true.
func (r *EKSConfigReconciler) storeBootstrapData(ctx context.Context, cluster *clusterv1.Cluster, config *eksbootstrapv1.EKSConfig, data []byte) error {
	log := logger.FromContext(ctx)

	// as secret creation and scope.Config status patch are not atomic operations
	// it is possible that secret creation happens but the config.Status patches are not applied
	secret := &corev1.Secret{}
	if err := r.Client.Get(ctx, client.ObjectKey{
		Name:      config.Name,
		Namespace: config.Namespace,
	}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			if secret, err = r.createBootstrapSecret(ctx, cluster, config, data); err != nil {
				return errors.Wrap(err, "failed to create bootstrap data secret for EKSConfig")
			}
			log.Info("created bootstrap data secret for EKSConfig", "secret", klog.KObj(secret))
		} else {
			return errors.Wrap(err, "failed to get data secret for EKSConfig")
		}
	} else {
		updated, err := r.updateBootstrapSecret(ctx, secret, data)
		if err != nil {
			return errors.Wrap(err, "failed to update data secret for EKSConfig")
		}
		if updated {
			log.Info("updated bootstrap data secret for EKSConfig", "secret", klog.KObj(secret))
		} else {
			log.Trace("no change in bootstrap data secret for EKSConfig", "secret", klog.KObj(secret))
		}
	}

	config.Status.DataSecretName = ptr.To[string](secret.Name)
	config.Status.Ready = true
	v1beta1conditions.MarkTrue(config, eksbootstrapv1.DataSecretAvailableCondition)
	return nil
}

// MachineToBootstrapMapFunc is a handler.ToRequestsFunc to be used to enqueue requests
// for EKSConfig reconciliation.
func (r *EKSConfigReconciler) MachineToBootstrapMapFunc(_ context.Context, o client.Object) []ctrl.Request {
	result := []ctrl.Request{}

	m, ok := o.(*clusterv1.Machine)
	if !ok {
		klog.Errorf("Expected a Machine but got a %T", o)
	}
	if m.Spec.Bootstrap.ConfigRef.IsDefined() && m.Spec.Bootstrap.ConfigRef.APIGroup == eksbootstrapv1.GroupVersion.Group && m.Spec.Bootstrap.ConfigRef.Kind == eksConfigKind {
		name := client.ObjectKey{Namespace: m.Namespace, Name: m.Spec.Bootstrap.ConfigRef.Name}
		result = append(result, ctrl.Request{NamespacedName: name})
	}
	return result
}

// MachinePoolToBootstrapMapFunc is a handler.ToRequestsFunc to be uses to enqueue requests
// for EKSConfig reconciliation.
func (r *EKSConfigReconciler) MachinePoolToBootstrapMapFunc(_ context.Context, o client.Object) []ctrl.Request {
	result := []ctrl.Request{}

	m, ok := o.(*clusterv1.MachinePool)
	if !ok {
		klog.Errorf("Expected a MachinePool but got a %T", o)
	}
	configRef := m.Spec.Template.Spec.Bootstrap.ConfigRef
	if configRef.IsDefined() && configRef.APIGroup == eksbootstrapv1.GroupVersion.Group && configRef.Kind == eksConfigKind {
		name := client.ObjectKey{Namespace: m.Namespace, Name: configRef.Name}
		result = append(result, ctrl.Request{NamespacedName: name})
	}

	return result
}

// ClusterToEKSConfigs is a handler.ToRequestsFunc to be used to enqueue requests for
// EKSConfig reconciliation.
func (r *EKSConfigReconciler) ClusterToEKSConfigs(_ context.Context, o client.Object) []ctrl.Request {
	result := []ctrl.Request{}

	c, ok := o.(*clusterv1.Cluster)
	if !ok {
		klog.Errorf("Expected a Cluster but got a %T", o)
	}

	selectors := []client.ListOption{
		client.InNamespace(c.Namespace),
		client.MatchingLabels{
			clusterv1.ClusterNameLabel: c.Name,
		},
	}

	machineList := &clusterv1.MachineList{}
	if err := r.Client.List(context.Background(), machineList, selectors...); err != nil {
		return nil
	}

	for _, m := range machineList.Items {
		if m.Spec.Bootstrap.ConfigRef.IsDefined() &&
			m.Spec.Bootstrap.ConfigRef.APIGroup == eksbootstrapv1.GroupVersion.Group &&
			m.Spec.Bootstrap.ConfigRef.Kind == eksConfigKind {
			name := client.ObjectKey{Namespace: m.Namespace, Name: m.Spec.Bootstrap.ConfigRef.Name}
			result = append(result, ctrl.Request{NamespacedName: name})
		}
	}

	return result
}

// Create the Secret containing bootstrap userdata.
func (r *EKSConfigReconciler) createBootstrapSecret(ctx context.Context, cluster *clusterv1.Cluster, config *eksbootstrapv1.EKSConfig, data []byte) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.Name,
			Namespace: config.Namespace,
			Labels: map[string]string{
				clusterv1.ClusterNameLabel: cluster.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: eksbootstrapv1.GroupVersion.String(),
					Kind:       eksConfigKind,
					Name:       config.Name,
					UID:        config.UID,
					Controller: ptr.To[bool](true),
				},
			},
		},
		Data: map[string][]byte{
			"value": data,
		},
		Type: clusterv1.ClusterSecretType,
	}
	return secret, r.Client.Create(ctx, secret)
}

// Update the userdata in the bootstrap Secret.
func (r *EKSConfigReconciler) updateBootstrapSecret(ctx context.Context, secret *corev1.Secret, data []byte) (bool, error) {
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	if !bytes.Equal(secret.Data["value"], data) {
		secret.Data["value"] = data
		return true, r.Client.Update(ctx, secret)
	}
	return false, nil
}

// transformEndpointForSecretRegion transforms commercial AWS endpoint to Secret region endpoint if needed.
// Example transformation:
//
//	Input:  https://XXXXX.gr7.us-east-1.eks.amazonaws.com
//	Output: https://XXXXX.gr7.us-isob-east-1.eks.sc2s.sgov.gov
func transformEndpointForSecretRegion(endpoint string, region string) string {
	// Only transform for Secret region us-isob-east-1
	if region != usIsoBEast1Region {
		return endpoint
	}

	// Transform commercial endpoint suffix to Secret region suffix
	// Pattern: .gr7.us-east-1.eks.amazonaws.com -> .gr7.us-isob-east-1.eks.sc2s.sgov.gov
	if strings.Contains(endpoint, ".eks.amazonaws.com") {
		transformed := strings.Replace(endpoint, ".gr7.us-east-1.eks.amazonaws.com", ".gr7.us-isob-east-1.eks.sc2s.sgov.gov", 1)
		return transformed
	}

	return endpoint
}
