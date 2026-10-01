# EKS access entries (EKS API) IAM access mode: CAPA and Palette design

| | |
|---|---|
| **Epic** | [PCP-4870](https://spectrocloud.atlassian.net/browse/PCP-4870) — Support EKS access entries (EKS API) IAM access mode |
| **Task** | [PCP-7715](https://spectrocloud.atlassian.net/browse/PCP-7715) — CAPA implementation to support IAM access entries |
| **Related** | [PCP-6715](https://spectrocloud.atlassian.net/browse/PCP-6715) (closed, default `api_and_config_map`), [SUS-1458](https://spectrocloud.atlassian.net/browse/SUS-1458) (customer driver), upstream [kubernetes-sigs/cluster-api-provider-aws#5583](https://github.com/kubernetes-sigs/cluster-api-provider-aws/pull/5583), [#6003](https://github.com/kubernetes-sigs/cluster-api-provider-aws/issues/6003) / [#6007](https://github.com/kubernetes-sigs/cluster-api-provider-aws/pull/6007) |
| **Repos** | `spectrocloud-public/cluster-api-provider-aws` (branch `PCP-7715`, base tag `v2.12.1-spectro-4.10.2`), `spectrocloud/palette`, `ally`, hapi / UI / Terraform / Crossplane (outside this doc) |
| **Status** | CAPA: implemented in the working tree, not committed. Palette: design only. |
| **Date** | 2026-10-01 |

---

## 1. Summary

AWS has deprecated the `aws-auth` ConfigMap for granting IAM principals access to EKS clusters and replaced it with
**access entries** (the "EKS API" authentication mode). Today Palette only supports the ConfigMap mode, configured
through the EKS pack (`managedControlPlane.iamAuthenticatorConfig`).

Key findings:

1. **CAPA already has the feature.** Upstream PR #5583 (`0cdd2b16a`, merged 2026-01-06) is in our fork, and Palette
   already pins the fork tag that contains it (`palette/go.mod:314` →
   `v2.12.1-spectro-4.10.2`). Palette's vendored CRDs already contain `accessConfig` and `accessEntries`.
   No port and no CAPA version bump are needed.
2. **The upstream implementation has gaps that break Palette's requirements.** PCP-7715 fixes them in the fork (§5).
   The fixes are generic CAPA bug fixes with no Palette-specific logic, so they can be sent upstream to keep fork
   drift small.
3. **Palette never sets these fields today.** There are zero references in Palette Go code. The Palette work (§7) is
   a separate deliverable under the epic.

---

## 2. Background

### 2.1 Two identity systems

| System | Identifies | Example |
|---|---|---|
| AWS IAM | AWS principals | `arn:aws:iam::123456789012:role/DevOps` |
| Kubernetes RBAC | Kubernetes users and groups | user `anish`, group `system:masters` |

EKS must translate an incoming IAM ARN into a Kubernetes user and groups. Kubernetes RBAC (`Role`, `RoleBinding`,
`ClusterRole`, `ClusterRoleBinding`) then decides what that user or group may do.

### 2.2 Request flow for `kubectl get pods -A`

1. kubectl reads the kubeconfig. The user has an `exec` block (`aws-iam-authenticator token -i <cluster>` or
   `aws eks get-token`).
2. The helper uses the ambient AWS credentials to build a **pre-signed STS `GetCallerIdentity` URL** with the
   `x-k8s-aws-id: <cluster>` header, and returns `k8s-aws-v1.<base64>` as a bearer token.
3. kubectl sends the request to the EKS endpoint. TLS is verified with `certificate-authority-data`.
4. EKS calls the pre-signed STS URL and learns the caller's IAM ARN.
5. **EKS translates the ARN to a Kubernetes user and groups.** This is the step this design changes:
   - `CONFIG_MAP` mode: lookup in `kube-system/aws-auth` (`mapRoles` / `mapUsers`).
   - `API` mode: lookup in the cluster's **access entries**.
6. Kubernetes RBAC authorizes the verb and resource. A missing mapping returns 401; missing RBAC returns 403.

### 2.3 The two mechanisms

| | `aws-auth` ConfigMap | Access entries (EKS API) |
|---|---|---|
| Where it lives | Inside the cluster (`kube-system`) | EKS control plane, outside the cluster |
| How it's changed | Editing YAML | `CreateAccessEntry` / `UpdateAccessEntry` / `DeleteAccessEntry` |
| Permissions | You write RBAC yourself | Optional AWS-managed **access policies** (`AmazonEKSClusterAdminPolicy`, `AmazonEKSAdminPolicy`, `AmazonEKSEditPolicy`, `AmazonEKSViewPolicy`, …), scoped to the `cluster` or to `namespace`s (wildcards such as `dev-*` are allowed) |
| Audit | None in AWS | CloudTrail |
| Failure mode | One typo locks everybody out | Validated by the API |
| Editable when the cluster is broken | No | Yes |

### 2.4 Authentication modes

| Mode (`cluster.accessConfig.authenticationMode`) | ConfigMap honoured | Access entries honoured |
|---|---|---|
| `CONFIG_MAP` | yes | no |
| `API_AND_CONFIG_MAP` | yes | yes |
| `API` | no | yes |

Mode changes are **one-way**: `CONFIG_MAP → API_AND_CONFIG_MAP → API`. Downgrades are rejected by EKS and by the
CAPA webhook.

### 2.5 Access entry types (EKS user guide, *Create access entries*)

| Type | Use | `kubernetesGroups` | Access policies |
|---|---|---|---|
| `STANDARD` (default) | Users and roles | allowed | allowed |
| `EC2_LINUX`, `EC2_WINDOWS` | Self-managed nodes | not allowed | not allowed |
| `FARGATE_LINUX` | Fargate pod execution role | not allowed | not allowed |
| `HYBRID_LINUX` | Hybrid nodes | not allowed | not allowed |
| `HYPERPOD_LINUX`, `EC2` (Auto Mode) | Node identities | not allowed | not allowed |

> "You can't use the `--kubernetes-groups` option when you specify a type other than `STANDARD`. You can't
> associate an access policy to this access entry, because its type is a value other than `STANDARD`."
> — Amazon EKS User Guide, *Create access entries*

### 2.6 Entries EKS creates on its own

- **The cluster creator.** With `bootstrapClusterCreatorAdminPermissions: true` (the CAPA default), EKS creates an
  admin access entry for the IAM principal that called `CreateCluster`. For Palette that is the cloud-account role.
  The entry carries **no CAPA ownership tag**.
- **Managed node group and Fargate roles.** EKS creates their `EC2_LINUX` / `FARGATE_LINUX` entries. Palette EKS only
  uses `AWSManagedMachinePool` and `AWSFargateProfile`, so the epic's question about worker-node entries is not a
  concern for Palette.
- **The generated username.** When `username` is not set, EKS generates one (for a role:
  `arn:aws:sts::<acct>:assumed-role/<role>/{{SessionName}}`). `DescribeAccessEntry` returns it.

---

## 3. Requirements (from PCP-4870)

| # | Requirement | Layer |
|---|---|---|
| R1 | Choose `API` or `API_AND_CONFIG_MAP` on day 0 and day 2 | Palette, CAPA |
| R2 | Users with pack ConfigMap IAM config (`iamAuthenticatorConfig`) are not affected | Palette, CAPA |
| R3 | Configure entries `[type, IAM principal, Kubernetes user, Kubernetes groups]` on day 0 and day 2 | Palette, CAPA |
| R4 | `STANDARD` entries can have one or more access policies, scoped to the cluster or to namespaces (with wildcards) | Palette, CAPA |
| R5 | The Palette cloud-account IAM role is automatically cluster admin | Palette, CAPA |
| R6 | A new section on the cluster configuration page | UI (out of scope) |
| R7 | Palette and Vertex; UI, API, Terraform, Crossplane | All |
| R8 | Day-2 changes to entries or policies must not repave nodes | Palette (verify) |
| R9 | Documentation updated | Docs |

Open questions from the epic, with answers:

- *Do we need an access entry for the worker-node bootstrap role?* No. Palette only uses managed node groups and
  Fargate, and EKS creates those entries itself (§2.6).
- *Can the bootstrap principal be non-admin?* No. CAPA's generated kubeconfig, which Palette also uses to install packs,
  authenticates as that principal. Palette must keep `bootstrapClusterCreatorAdminPermissions: true`.

---

## 4. Current state (before this change)

### 4.1 CAPA API (`controlplane/eks/api/v1beta2/awsmanagedcontrolplane_types.go`)

```go
// AWSManagedControlPlaneSpec
AccessConfig  *AccessConfig `json:"accessConfig,omitempty"`
AccessEntries []AccessEntry `json:"accessEntries,omitempty"` // top level, not inside AccessConfig

type AccessConfig struct {
	// +kubebuilder:default=config_map
	// +kubebuilder:validation:Enum=config_map;api;api_and_config_map
	AuthenticationMode EKSAuthenticationMode `json:"authenticationMode,omitempty"`
	// +kubebuilder:default=true
	BootstrapClusterCreatorAdminPermissions *bool `json:"bootstrapClusterCreatorAdminPermissions,omitempty"`
}

type AccessEntry struct {
	PrincipalARN     string                  `json:"principalARN"`
	Type             AccessEntryType         `json:"type,omitempty"` // +kubebuilder:default=standard
	KubernetesGroups []string                `json:"kubernetesGroups,omitempty"`
	Username         string                  `json:"username,omitempty"`
	AccessPolicies   []AccessPolicyReference `json:"accessPolicies,omitempty"` // MaxItems=20
}

type AccessPolicyReference struct {
	PolicyARN   string      `json:"policyARN"`
	AccessScope AccessScope `json:"accessScope"` // Type: cluster|namespace (default cluster), Namespaces
}
```

Enum values are lower case (`config_map`, `api`, `api_and_config_map`, `standard`, …). `APIValue()` upper-cases them
for the AWS SDK.

### 4.2 CAPA reconcile flow

```
controlplane/eks/controllers/awsmanagedcontrolplane_controller.go:309 reconcileNormal
 ├─ :358 ekssvc.ReconcileControlPlane                       (pkg/cloud/services/eks/cluster.go)
 │    ├─ :436 createCluster        → CreateClusterInput.AccessConfig{AuthenticationMode, BootstrapClusterCreatorAdminPermissions}
 │    ├─ :86  wait if CREATING/UPDATING (waitForClusterActive)
 │    ├─ :123 reconcileClusterConfig
 │    ├─ :127 reconcileAccessConfig   → UpdateClusterConfig(authMode); WaitUntilClusterUpdating
 │    ├─ :131 reconcileAccessEntries  → accessentry.go
 │    ├─ :135 reconcileLogging, :139 encryption, :143 tags, :147 OIDC   (skipped if an earlier step fails)
 └─ :340/:378 iamauth.ReconcileIAMAuthenticator   → always writes aws-auth (node roles + spec mappings), any mode
```

"Managed" means the entry carries the tag `kubernetes.io/cluster/<scope.Name()> = owned`, which `createAccessEntry`
adds. Only managed entries are updated or deleted.

### 4.3 Upstream algorithm (`accessentry.go`, before this change)

```
1. len(spec.accessEntries) == 0           → return            ← gap A
2. mode not api / api_and_config_map      → return
3. list entries; describe each; keep only tagged ("managed")  ← describe errors skipped (gap B)
4. for each spec entry:
      in managed → updateAccessEntry      (recreate if type OR username differ ← #6003)
      else       → createAccessEntry      ← fails forever if it exists untagged (gap B)
5. managed entries not in spec → delete
policies: associate every spec policy on every pass (gap E); disassociate the rest;
          skipped only for ec2_linux/ec2_windows (gap D)
```

### 4.4 Palette (`spectrocloud/palette`)

- `pkg/clusterdeployer/controlplane/controlplane_managed.go:22` → `pkg/provider/aws/aws_managed.go:208`
  `CreateUpdateManagedControlPlane` → `:428 getDesiredManagedControlPlane`. Nothing sets `AccessConfig` or
  `AccessEntries`.
- Pack aws-auth: `:811 getMCPIAMAuthenticatorConfig` reads `managedControlPlane.iamAuthenticatorConfig` and maps it
  onto `AMCP.spec.iamAuthenticatorConfig`.
- Day 2: `:943 shouldUpgradeMCP`
  - `:975` `allowedUpgradePaths` is applied unconditionally.
  - `:989` `packUpgradePaths` is gated by the Hubble hash.
  - `:264-272` copies a whitelist of fields onto the existing object, then the passthrough is re-applied.
- Cloud-account principal: `aws_account.go:91-175`.
  - STS → `Sts.Arn`, used via `AWSClusterRoleIdentity`.
  - Pod identity → `IamRoleArn`.
  - Static keys → IAM user ARN, not known to Palette.
  - Palette never adds this principal to `mapRoles`; it relies on EKS's creator-admin.
- Node repave decisions only look at `AWSManagedMachinePool` (`shouldDoMMPRollingUpgrade`), so AMCP-only changes
  do not roll nodes.
- Users can already set `accessConfig` / `accessEntries` through the `overrideClusterAPIConfig` passthrough.

---

## 5. CAPA changes (PCP-7715)

All changes live inside the access-entry feature. No API fields are added, so there are no `v1beta1` conversion
changes.

### 5.1 Gap A: removing the last entry never deletes it (security)

**Problem.** Step 1 returns when the spec list is empty. That is exactly the case where every managed entry must be
deleted. Removing the last user leaves their access in place.

**Change.** The decision depends only on the mode:

```go
func (s *Service) reconcileAccessEntries(ctx context.Context) error {
	// An empty spec list is not a reason to skip: entries previously created by the
	// controller must still be deleted when the user removes the last one.
	if !accessEntriesEnabled(s.scope.ControlPlane.Spec.AccessConfig) {
		s.scope.Info("access mode is not api or api_and_config_map, skipping reconcile")
		return nil
	}
	...
}

// accessEntriesEnabled returns true when the authentication mode allows access entries.
func accessEntriesEnabled(accessConfig *ekscontrolplanev1.AccessConfig) bool {
	if accessConfig == nil {
		return false
	}
	return accessConfig.AuthenticationMode == ekscontrolplanev1.EKSAuthenticationModeAPI ||
		accessConfig.AuthenticationMode == ekscontrolplanev1.EKSAuthenticationModeAPIAndConfigMap
}
```

Untagged entries (creator, nodes, manual ones) stay safe, because the delete loop only removes tagged entries.

### 5.2 Gap B: an entry that exists but isn't ours

**Problem.**

1. If the spec names a principal that exists without CAPA's tag, CAPA calls `CreateAccessEntry` and gets
   `ResourceInUseException` on every pass. The most common case for Palette is the cloud-account role (R5), whose
   creator entry EKS made. Because `reconcileAccessEntries` fails, logging, encryption, tags and OIDC
   (`cluster.go:135-147`) also stop reconciling for the cluster.
2. A failed `DescribeAccessEntry` was logged and skipped. A managed entry then looked unmanaged, so it was neither
   updated nor deleted.
3. Fully adopting an untagged entry is dangerous. `reconcileAccessPolicies` disassociates any policy that isn't in the
   spec. Listing the creator ARN with only `ViewPolicy` would strip `ClusterAdminPolicy` from the identity CAPA and
   Palette use, which locks Palette out of its own cluster.

**Change.** List every entry with a managed flag, return describe errors, and handle three cases:

```go
// getExistingAccessEntries returns every access entry of the cluster keyed by principal ARN.
// The value is true when the entry carries the controller's ownership tag.
func (s *Service) getExistingAccessEntries(ctx context.Context) (map[string]bool, error) {
	...
			if err != nil {
				// Skipping the entry would make a managed entry look unmanaged, so it would be
				// neither updated nor deleted. Fail and retry on the next reconcile instead.
				return nil, errors.Wrapf(err, "failed to describe access entry for principal %s", principalArn)
			}

			_, managed := describeOutput.AccessEntry.Tags[managedTag]
			existingAccessEntries[principalArn] = managed
	...
}

	for _, accessEntry := range s.scope.ControlPlane.Spec.AccessEntries {
		managed, exists := existingAccessEntries[accessEntry.PrincipalARN]
		switch {
		case !exists:
			// createAccessEntry (tags it as owned)
		case managed:
			// updateAccessEntry (full management)
		default:
			// The entry exists but was not created by this controller, e.g. the cluster creator
			// entry EKS adds when bootstrapClusterCreatorAdminPermissions is true. Only add the
			// requested access policies: recreating it, deleting it or disassociating its policies
			// could remove the controller's own cluster-admin access.
			record.Warnf(s.scope.ControlPlane, "AccessEntryNotManaged", "Access entry for principal %s is not managed by the controller: type, username and kubernetesGroups are not applied, only access policies are associated", accessEntry.PrincipalARN)
			if err := s.associateAccessPolicies(ctx, accessEntry); err != nil { ... }
		}
		delete(existingAccessEntries, accessEntry.PrincipalARN)
	}

	for principalArn, managed := range existingAccessEntries {
		if !managed {
			continue
		}
		// deleteAccessEntry
	}
```

| Entry state | Action |
|---|---|
| Not in AWS | Create, tag as owned, reconcile policies |
| In AWS, tagged | Full update: type change recreates; username and groups updated in place; policies reconciled both ways |
| In AWS, untagged, in spec | **Additive only:** associate missing or changed policies; never recreate, delete or disassociate; warning event |
| In AWS, untagged, not in spec | Ignored |
| In AWS, tagged, not in spec | Deleted |

### 5.3 Gap C: entries reconciled while the auth-mode change is still running

**Problem.** `reconcileAccessConfig` only waited for `UPDATING`, and access entries were reconciled straight after,
against a cluster still applying the mode change. A day-2 "switch mode and add entries" save could then produce error
events until a later reconcile succeeded.

**Change.** After the mode update is issued, wait for `ACTIVE`. This uses the lower-level `WaitUntilClusterActive`,
not `waitForClusterActive`, which would also patch the object's status in the middle of the reconcile.

```go
		// Access entries are reconciled right after this and require the new authentication
		// mode to be in effect. Wait for the authentication mode change to finish so they are
		// not reconciled while the cluster is still UPDATING.
		if err := s.EKSClient.WaitUntilClusterActive(
			ctx,
			&eks.DescribeClusterInput{Name: aws.String(s.scope.KubernetesClusterName())},
			s.scope.MaxWaitActiveUpdateDelete,
		); err != nil {
			return errors.Wrap(err, "failed waiting for EKS cluster auth config update to complete")
		}
```

Whether EKS actually rejects entry calls during `UPDATING` is **not verified** (spike S1). The wait is safe either way.
It holds a reconcile worker for the duration of the mode change, as the existing wait at `cluster.go:86` already does.

### 5.4 Upstream #6003: delete + recreate on every reconcile (adopted from upstream #6007)

**Problem.**

1. `updateAccessEntry` recreated the entry when `spec.username != existingUsername`. When `username` is unset, EKS
   generates one (§2.6), so `"" != generated` is always true. **Every entry without a username was deleted and
   recreated on every reconcile**, briefly removing its access (upstream issue #6003, "breaking auth"). AWS recommends
   leaving `username` unset, so Palette would hit this constantly.
2. An empty spec `type` compared `""` with `"STANDARD"`, which also caused a recreate.
3. A nil `describeOutput.AccessEntry.Type` would panic.

**Change.** Use upstream `main`'s `updateAccessEntry` from PR #6007 as-is, plus an `aws.ToString` nil guard:

```go
	// Normalize empty spec Type to STANDARD to match what EKS reports for a
	// default STANDARD entry, so an unset Type is not seen as drift.
	desiredType := accessEntry.Type
	if desiredType == "" {
		desiredType = ekscontrolplanev1.AccessEntryTypeStandard
	}

	// Type is the only immutable field, so it is the only one requiring a recreate.
	// UpdateAccessEntry accepts username and Kubernetes groups.
	if *desiredType.APIValue() != aws.ToString(describeOutput.AccessEntry.Type) {
		// deleteAccessEntry + createAccessEntry
	}

	... // groups compared sorted → needsUpdate

	// An unset username means EKS generates one, so the generated value is not drift.
	if accessEntry.Username != "" && accessEntry.Username != existingUsername {
		updateInput.Username = &accessEntry.Username
		needsUpdate = true
	}

	if needsUpdate {
		// UpdateAccessEntry
	}
```

Behaviour changes:
- A username change is now an **in-place update**, not a recreate.
- Removing `username` from the spec keeps whatever username EKS has. Upstream made the same trade-off.

### 5.5 Gap D: webhook checks weaker than EKS rules

`controlplane/eks/webhooks/awsmanagedcontrolplane_webhook.go` `validateAccessEntries`:

| Rule | Before | After |
|---|---|---|
| Duplicate `principalARN` | accepted; the second one fails forever (like gap B) | `field.Duplicate` |
| Duplicate `policyARN` within one entry | accepted | `field.Duplicate` |
| `kubernetesGroups` on a non-standard type | only `ec2_linux` / `ec2_windows` rejected | every non-standard type rejected |
| `accessPolicies` on a non-standard type | only `ec2_linux` / `ec2_windows` rejected | every non-standard type rejected |
| Empty `type` | n/a | treated as `standard` (CRD default) |

```go
	principalARNs := make(map[string]bool, len(r.Spec.AccessEntries))
	for i, entry := range r.Spec.AccessEntries {
		// Each principal can only have one access entry in EKS
		if principalARNs[entry.PrincipalARN] {
			allErrs = append(allErrs,
				field.Duplicate(field.NewPath("spec", "accessEntries").Index(i).Child("principalARN"), entry.PrincipalARN),
			)
		}
		principalARNs[entry.PrincipalARN] = true

		// EKS only allows kubernetes groups and access policies on standard access entries
		isStandard := entry.Type == "" || entry.Type == ekscontrolplanev1.AccessEntryTypeStandard
		if !isStandard && len(entry.KubernetesGroups) > 0 {
			// "kubernetesGroups can only be specified when type is standard"
		}
		if !isStandard && len(entry.AccessPolicies) > 0 {
			// "accessPolicies can only be specified when type is standard"
		}

		policyARNs := make(map[string]bool, len(entry.AccessPolicies))
		for j, policy := range entry.AccessPolicies {
			// field.Duplicate on spec.accessEntries[i].accessPolicies[j].policyARN
		}
		...
	}
```

Supporting changes:

- The service layer mirrors the policy rule. `reconcileAccessPolicies` skips every non-standard type, not only EC2.
  The comparison is case-insensitive, matching `APIValue()`:

  ```go
  // supportsAccessPolicies returns true when access policies can be associated with the access
  // entry type. EKS only allows access policies on standard access entries.
  func supportsAccessPolicies(entryType ekscontrolplanev1.AccessEntryType) bool {
  	return entryType == "" || strings.EqualFold(string(entryType), string(ekscontrolplanev1.AccessEntryTypeStandard))
  }
  ```

- API doc comments on `KubernetesGroups` and `AccessPolicies` now read "Can only be specified if Type is
  \"standard\"". The CRD descriptions were regenerated with `make generate-go-apis`; four description lines changed
  across the two CRD YAMLs.

**Not changed (spike S2).** A direct `config_map → api` mode change is still allowed by the webhook. The EKS API
reference does not state whether `CONFIG_MAP → API` without `API_AND_CONFIG_MAP` in between is rejected.

### 5.6 Gap E: policies re-associated on every reconcile

**Problem.** `AssociateAccessPolicy` was called for every policy of every entry on every pass, which risks AWS API
throttling across many clusters in one account.

**Change.** Only associate a policy when it is missing or its scope changed:

```go
// associateMissingAccessPolicies associates the policies of the access entry that are not yet
// associated, or whose access scope differs from the associated one. Unchanged policies are
// skipped to avoid an AWS call per policy on every reconcile.
func (s *Service) associateMissingAccessPolicies(ctx context.Context, accessEntry ekscontrolplanev1.AccessEntry, existingPolicies map[string]ekstypes.AssociatedAccessPolicy) error {
	for _, policy := range accessEntry.AccessPolicies {
		if existing, ok := existingPolicies[policy.PolicyARN]; ok && accessScopeEqual(existing.AccessScope, policy.AccessScope) {
			continue
		}
		// AssociateAccessPolicy (namespaces only for namespace scope)
	}
	return nil
}

// accessScopeEqual compares the access scope associated in EKS with the desired one.
// The EKS scope type is upper case and namespaces are compared ignoring order.
func accessScopeEqual(existing *ekstypes.AccessScope, desired ekscontrolplanev1.AccessScope) bool { ... }
```

`reconcileAccessPolicies` (managed entries) = `associateMissingAccessPolicies` + disassociate policies not in the
spec. `associateAccessPolicies` (unmanaged entries) = `associateMissingAccessPolicies` only.

### 5.7 Explicitly not changed in CAPA

- No new API fields or CRD schema changes (descriptions only), and no `v1beta1` conversion work.
- `iamauth.ReconcileIAMAuthenticator` keeps writing `aws-auth` in every mode. It is harmless in `api` mode and
  keeps upstream parity.
- No access entries for self-managed node roles (`AWSMachinePool`, `AWSMachineTemplate`) in `api` mode. This is a
  known upstream limitation, and Palette does not use those pool types.
- No CAPA-side "add my own identity as admin". That stays in Palette (§7.3), so CAPA stays generic.
- The one `DescribeAccessEntry` call per listed entry is unchanged (it predates this work).

### 5.8 CAPA files changed

| File | Change |
|---|---|
| `pkg/cloud/services/eks/accessentry.go` | Gaps A, B, D (service side), E; upstream #6007 `updateAccessEntry` |
| `pkg/cloud/services/eks/cluster.go` | Gap C: wait for `ACTIVE` after the auth-mode update |
| `controlplane/eks/webhooks/awsmanagedcontrolplane_webhook.go` | Gap D |
| `controlplane/eks/api/v1beta2/awsmanagedcontrolplane_types.go` | Doc comments only |
| `config/crd/bases/controlplane.cluster.x-k8s.io_awsmanagedcontrolplanes.yaml` | Generated (descriptions) |
| `config/crd/bases/controlplane.cluster.x-k8s.io_awsmanagedcontrolplanetemplates.yaml` | Generated (descriptions) |
| `pkg/cloud/services/eks/accessentry_test.go` | New and updated cases (§9.1) |
| `pkg/cloud/services/eks/cluster_test.go` | Wait-for-`ACTIVE` cases |
| `controlplane/eks/webhooks/awsmanagedcontrolplane_webhook_test.go` | New webhook cases |

---

## 6. CAPA flow after the change

```
reconcileAccessConfig
  mode differs? → UpdateClusterConfig → WaitUntilClusterUpdating → WaitUntilClusterActive   (C)
reconcileAccessEntries
  mode not api/api_and_config_map → return            (empty list no longer skips: A)
  existing := list + describe all (managed flag; describe error → return)   (B)
  for spec entry:
     absent    → create (tag) → policies: associate missing/changed, disassociate extra   (E)
     managed   → update: type differs → recreate; username/groups → UpdateAccessEntry (#6007)
                 → policies as above
     unmanaged → associate missing/changed policies only; warning event                    (B)
  managed entries not in spec → delete                                                      (A)
webhook: duplicates, standard-only groups/policies, ratchet (unchanged)                     (D)
```

---

## 7. Palette design (follow-up deliverable under PCP-4870)

This section is the design only. No Palette code has been changed.

### 7.1 Where the setting lives

It is a **cloud-config field, not a pack value**. The epic asks for a new section on the cluster configuration page,
and says the pack's `aws-auth` experience must stay the source of truth. `nil` means today's behaviour, which is
`config_map` with the pack `aws-auth`.

### 7.2 Types (`api/v1/awscloudconfig_types.go` and `api/v1alpha1/awscloudconfig_types.go`, in `EksClusterConfig`)

Palette owns its own copy of the types instead of embedding CAPA's. `ally` compiles Palette's `api/v1alpha1` against
an older CAPA pin that has no `AccessEntry` type, and embedding would also tie Palette's public API to CAPA field names.
The JSON names match CAPA, so mapping is a 1:1 copy. v1alpha1 ↔ v1 conversion is a JSON round-trip
(`api/v1alpha1/conversion_helpers.go`), so `make generate manifests` is the only step needed.

```go
	// AccessConfig enables EKS access entries. nil keeps the aws-auth ConfigMap-only mode
	// configured through the EKS pack.
	// +optional
	AccessConfig *EksAccessConfig `json:"accessConfig,omitempty"`

type EksAccessConfig struct {
	// +kubebuilder:validation:Enum=api;api_and_config_map
	AuthenticationMode string `json:"authenticationMode"`
	// +optional
	AccessEntries []EksAccessEntry `json:"accessEntries,omitempty"`
}

type EksAccessEntry struct {
	// +kubebuilder:validation:Required
	PrincipalARN string `json:"principalARN"`
	// +kubebuilder:validation:Enum=standard;ec2_linux;ec2_windows;fargate_linux;ec2;hybrid_linux;hyperpod_linux
	// +optional
	Type             string   `json:"type,omitempty"`
	Username         string   `json:"username,omitempty"`
	KubernetesGroups []string `json:"kubernetesGroups,omitempty"`
	// +kubebuilder:validation:MaxItems=20
	AccessPolicies []EksAccessPolicy `json:"accessPolicies,omitempty"`
}

type EksAccessPolicy struct {
	PolicyARN   string         `json:"policyARN"`
	AccessScope EksAccessScope `json:"accessScope"`
}

type EksAccessScope struct {
	// +kubebuilder:validation:Enum=cluster;namespace
	Type       string   `json:"type,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"` // wildcards such as "dev-*" pass through to EKS
}
```

### 7.3 Builder (`pkg/provider/aws/aws_managed.go` `getDesiredManagedControlPlane`, :428)

Add `getMCPAccessConfig(cluster, clusterConfig, account)`, following the `getMCPIAMAuthenticatorConfig` pattern:

```go
	if clusterConfig.AccessConfig != nil {
		mcp.Spec.AccessConfig = &ekscontrolplanev1.AccessConfig{
			AuthenticationMode: ekscontrolplanev1.EKSAuthenticationMode(clusterConfig.AccessConfig.AuthenticationMode),
			// Mirror the CRD default: the stored AMCP always has it, so leaving it nil would diff forever.
			BootstrapClusterCreatorAdminPermissions: ptr.To(true),
		}
		mcp.Spec.AccessEntries = toCAPAAccessEntries(clusterConfig.AccessConfig.AccessEntries) // fills type=standard, scope.type=cluster
		mcp.Spec.AccessEntries = appendCloudAccountAdminEntry(mcp.Spec.AccessEntries, account)  // R5
	}
```

Rules:

1. **Mirror the CRD defaults explicitly** (`type: standard`, `accessScope.type: cluster`,
   `bootstrapClusterCreatorAdminPermissions: true`). Otherwise the API-server-defaulted stored object differs from
   desired on every loop, and `ShouldUpgrade` triggers an update every time.
2. **Never send `AccessConfig: nil` once it has been set.** The CAPA webhook rejects removing it. Read the existing
   AMCP and keep its value.
3. **Cloud-account admin entry (R5).**
   - Add a `standard` entry for the cloud-account principal with `AmazonEKSClusterAdminPolicy`, cluster scope.
   - The principal is `Sts.Arn` for STS accounts and `IamRoleArn` for pod identity. Static keys need STS
     `GetCallerIdentity`; the helpers already exist in `pkg/podidentity/job.go:118` and
     `pkg/eksadoption/discovery.go:845`.
   - CAPA gap B makes this safe when EKS has already created the creator entry. CAPA adopts it additively and never
     strips admin from it.
   - Do **not** set `username` or `kubernetesGroups` on this entry. They are not applied to an unmanaged entry
     (§5.2), and leaving them unset avoids a misleading spec.
   - Reject a user-supplied entry with the same ARN (§7.6). Palette owns that entry.
   - This choice is still open: the bot design (`origin/claude/PCP-4870-design`) instead *rejects* the cloud-account
     ARN and relies only on the creator-admin rule (§12, D3).
4. **Pack aws-auth coexistence (R2).** The pack `iamAuthenticatorConfig` mapping is unchanged. If the mode is `api`
   and the pack has `mapRoles` / `mapUsers`, emit a Warning event ("aws-auth mappings are ignored in api mode"). The
   CloudConfig webhook cannot see pack values, so this can only be a warning.

### 7.4 Day 2 (`shouldUpgradeMCP` :943, and the copy whitelist :264-272)

These are cloud-config fields, so they go in the **ungated** `allowedUpgradePaths`, like `EndpointAccess`:

```go
	allowedUpgradePaths := []string{
		"Version",
		"SSHKeyName",
		"AdditionalTags",
		"EndpointAccess.*",
		"Bastion.Enabled",
		"EncryptionConfig.*",
		"AccessConfig.AuthenticationMode",
		"AccessEntries",
	}
```

```go
	// CreateUpdateManagedControlPlane, update block
	mcpExisting.Spec.AccessConfig = mergeAccessConfig(mcpExisting.Spec.AccessConfig, mcpDesired.Spec.AccessConfig) // keeps BootstrapClusterCreatorAdminPermissions
	mcpExisting.Spec.AccessEntries = mcpDesired.Spec.AccessEntries
```

`bootstrapClusterCreatorAdminPermissions` is only used at create time. The CAPA webhook logs changes to it and
ignores them, so keep the existing value.

**Repave (R8).** AMCP-only changes go through the "MCP upgrade" path (event and history entry) and never touch
`AWSManagedMachinePool`, so nodes don't roll. A mode change runs `UpdateClusterConfig`, which updates the control
plane only, with no node repave. This must still be verified (§9.3).

### 7.5 Precedence with the passthrough

`overrideClusterAPIConfig.awsManagedControlPlane` is applied last as an RFC 7396 merge patch, where arrays are
replaced whole. If both the typed field and the passthrough set `accessEntries`, the passthrough wins. Document this;
the passthrough stays as a stopgap for customers who need the feature before the UI ships.

### 7.6 Palette webhook (`api/v1*/awscloudconfig_webhook.go` ValidateCreate/ValidateUpdate)

These catch errors at submit time instead of as a failing CAPA reconcile:

- Mode is one-way. On update: `accessConfig` cannot be removed once set, and `api` cannot go back to
  `api_and_config_map`.
- Duplicate principal ARNs; duplicate policy ARNs within an entry.
- `kubernetesGroups` and `accessPolicies` only on `standard` entries.
- `namespaces` required for `namespace` scope, and rejected for `cluster` scope.
- An entry with the cloud-account principal ARN is rejected, because Palette adds it.

### 7.7 Other Palette touch points

| Area | Change |
|---|---|
| EKS adoption (`pkg/eksadoption/capa_mapper.go:364` TODO, `pack_values.go`, `pack_diff.go`, `pkg/adoption/dry_run_client.go`) | Copy the discovered mode and entries, so adopted `api`-mode clusters don't show diffs or regress. Can follow in a later ticket. |
| Pivot (`aws_pivot.go:96`) | No change; it does a full DeepCopy. |
| `ally` (`eks_cloud_config_converter.go` `fromApiEksClusterConfig`) | Map the hapi fields to Palette `v1alpha1`. Bump the `palette` and `hapi` pseudo-versions. ally's CAPA `replace` stays unchanged. |
| hapi / UI / TF / Crossplane / docs | New `V1EksClusterConfig.accessConfig` with the §7.2 shape. UI section (mode, entries, type and principal dropdowns, policies). `eks:ListAccessPolicies` for the policy dropdown. |
| Vertex | No Vertex-specific EKS code exists; same code path. |

### 7.8 Merge order

| # | Repo | Change | Depends on |
|---|---|---|---|
| 1 | `cluster-api-provider-aws` | This PR (PCP-7715); build and publish the CAPA image Palette deploys | — |
| 2 | `palette` | Types, CRD regen, webhook, provider, go.mod bump to step 1's tag | 1 |
| 3 | hapi / Hubble / UI / TF / Crossplane | Fields and UI | in parallel |
| 4 | `ally` | Converter and version bumps | 2, 3 |

Step 2 has no effect in production until step 4 ships, because nothing writes the field yet.

---

## 8. Edge cases

| # | Scenario | Expected behaviour | Where |
|---|---|---|---|
| 1 | Existing cluster, no `accessConfig` | No change; no access-entry calls; `aws-auth` keeps working | CAPA gate |
| 2 | New cluster, `api` mode, no user entries | Only creator and node entries exist; one list per reconcile | A |
| 3 | User removes the last entry | Managed entry deleted | A |
| 4 | Spec lists the creator / cloud-account ARN | Adopted: policies added, never deleted or disassociated; warning event | B |
| 5 | Spec entry for the creator lacks the admin policy | Admin policy stays; no lockout | B |
| 6 | Spec entry for the creator sets username or groups | Not applied (warning event says so) | B |
| 7 | Entry made by hand with the AWS CLI | Not in spec and untagged → ignored | B |
| 8 | EKS node group / Fargate entries | Untagged → never touched | B |
| 9 | `DescribeAccessEntry` transient error | Reconcile returns the error and retries; no wrong create or skip | B |
| 10 | Duplicate principal ARN in spec | Rejected by the webhook | D |
| 11 | Duplicate policy ARN in one entry | Rejected by the webhook | D |
| 12 | Same policy on two different entries | Allowed | D |
| 13 | Groups or policies on fargate, hybrid, ec2, … | Rejected by the webhook; the service also skips policies | D |
| 14 | `type` unset | Treated as `standard` everywhere; no recreate loop | #6007, D |
| 15 | `username` unset | EKS-generated username kept; no recreate loop | #6007 |
| 16 | `username` changed or added | `UpdateAccessEntry` in place | #6007 |
| 17 | `type` changed | Delete + create (EKS type is immutable) | unchanged |
| 18 | Only groups changed | `UpdateAccessEntry` (sorted compare) | unchanged |
| 19 | Policy unchanged | No API call | E |
| 20 | Namespaces reordered | No API call | E |
| 21 | Namespaces changed, or scope cluster ↔ namespace | Re-associate with the new scope | E |
| 22 | Policy removed from a managed entry | Disassociated | unchanged |
| 23 | Wildcard namespace (`dev-*`) | Passed through as-is | unchanged |
| 24 | Day-2 mode switch plus new entries in one save | Mode update → wait `ACTIVE` → entries in the same pass | C |
| 25 | Wait for `ACTIVE` times out | Reconcile error, retried | C |
| 26 | Mode downgrade, or removing `accessConfig` | Rejected by the webhook (CAPA, and Palette §7.6) | existing |
| 27 | Entries with mode `config_map` | Rejected by the webhook | existing |
| 28 | `config_map → api` directly | Allowed for now; spike S2 | open |
| 29 | `bootstrapClusterCreatorAdminPermissions` changed on day 2 | Logged and ignored by the webhook; Palette keeps the existing value | existing |
| 30 | Pack `mapRoles` with mode `api` | Mappings ignored by EKS; Palette warning event | Palette |
| 31 | Cloud-account role changes on day 2 | New entry created first, old managed entry deleted after (loop order) | B, Palette |
| 32 | Controller IAM lacks `eks:*AccessEntr*` / `*AccessPolic*` | AccessDenied in reconcile; docs must list the permissions | docs |
| 33 | Any entry, policy or mode change | No node repave | Palette (verify) |
| 34 | CRD defaults vs. Palette desired | No perpetual update loop | Palette §7.3 |

---

## 9. Test plan

### 9.1 CAPA unit tests (implemented)

Table-driven, gomock `mock_eksiface`, Gomega, following the existing `accessentry_test.go` harness.

| Test | Cases |
|---|---|
| `TestReconcileAccessEntries` | no entries (now lists); `config_map` skips all calls; **empty spec deletes managed, keeps unmanaged**; **unmanaged entry only associates missing policies (no Create/Update/Delete/Disassociate)**; **unmanaged entry without policies makes no changes**; **describe error returned**; **list error returned**; create; groups update; delete; ignore untagged |
| `TestReconcileAccessPolicies` | ec2_linux / ec2_windows / **fargate_linux** skip; **unchanged cluster policy not re-associated**; **reordered namespaces not re-associated**; **changed namespaces re-associated**; **namespace → cluster re-associated**; associate new; disassociate; namespace scoped |
| `TestUpdateAccessEntry` | no updates; type change recreates (fargate: no policy calls); **username change updates in place**; groups update; **unset username keeps EKS-generated username**; **username added updates in place**; **unset type treated as standard**; nil username with group update |
| `TestAccessScopeEqual` | nil existing; case-insensitive type; different type; namespace order; namespace removed |
| `TestReconcileAccessConfig` | no change; mode change **waits for `ACTIVE`**; API error; **wait timeout returns error** |
| `TestWebhookValidateAccessEntries` | existing cases; **policies rejected on fargate and hybrid**; **groups rejected on fargate and hybrid**; **type unset accepted with policies or groups**; **duplicate principal**; **duplicate policy in an entry**; **same policy on different entries accepted**; **fargate without groups or policies accepted** |

Bold cases are new or changed in this work. The three username cases and the cases that re-associated unchanged
policies were changed **on purpose** to match the new behaviour.

### 9.2 CAPA results (local, 2026-10-01)

- Changed packages pass: `pkg/cloud/services/eks`, `controlplane/eks/webhooks` (envtest 1.34.0),
  `controlplane/eks/controllers`, `controlplane/eks/api/v1beta1`.
- `go vet` is clean. golangci-lint v2.7.0 (the repo pin) reports nothing in any changed file. The 11 findings it does
  report are in untouched files.
- `make generate-go-apis` changes only the 4 CRD description lines.
- Full `go test ./...`: 49–50 packages ok. Failures that **also fail on clean HEAD `0ef7739d7`**, and are therefore
  not caused by this change:
  - `pkg/cloud/services/eks TestUpdateTagsForEKSManagedSecurityGroup` (expects 7 tags, gets 6; PCP-3571 test)
  - `api/v1beta1 TestFuzzyConversion`
  - `bootstrap/eks/controllers TestNodeadmConfigReconciler_*` (60s timeouts)
  - `controlplane/rosa/controllers TestReconcileExternalAuthKubeconfigSecrets` failed once, then passed 5/5 re-runs.
    It is flaky, and the package does not depend on the changed packages.

### 9.3 Spikes and E2E on a real EKS cluster (to do)

| ID | Question | Decides |
|---|---|---|
| S1 | Does EKS reject access entry calls while an auth-mode update is `UPDATING`? | Whether gap C is required (it's harmless either way) |
| S2 | Is `CONFIG_MAP → API` directly allowed by EKS? | Whether the webhook should block it (edge 28) |
| S3 | After a day-2 `CONFIG_MAP → API_AND_CONFIG_MAP` switch on an existing cluster, does EKS create the creator entry? | Confirms R5 for brownfield clusters; gap B covers either outcome |
| S4 | Node instance IDs before and after every day-2 step | R8, no repave |

E2E matrix (Palette and Vertex; commercial and GovCloud partitions):

1. Day 0 `api_and_config_map` with a `standard` entry and a namespace-scoped policy (`dev-*`).
2. Day 2: add, update (groups, username, policy scope), and remove all entries.
3. Day 2: `config_map → api_and_config_map` on an existing cluster, with pack `aws-auth` users still working.
4. `api` mode warning event.
5. The cloud-account entry keeps `AmazonEKSClusterAdminPolicy` throughout.
6. `aws eks list-access-entries` and `list-associated-access-policies` match the spec after every step.
7. Node groups stay `Ready`, with no instance replacement.

---

## 10. Impacts

| Area | Impact |
|---|---|
| Backward compatibility | Clusters without `accessConfig` are unchanged. Clusters already using `accessConfig` through the passthrough get the fixes: an empty list now deletes managed entries (intended), and the recreate loop stops. |
| Behaviour change | A username change is now an in-place update. Removing `username` keeps the EKS value. |
| Security | Fixes access not being revoked (gap A) and the auth flapping (#6003). Prevents controller lockout (gap B). |
| AWS API usage | `api` modes now list and describe entries every reconcile even with an empty spec. Unchanged policies are no longer re-associated. |
| Reconcile latency | A mode change blocks the worker until `ACTIVE`, the same pattern as the existing waits. |
| Events | `AccessEntryNotManaged` warning on each reconcile for adopted entries; Kubernetes aggregates repeats with a count. |
| IAM permissions | `eks:CreateAccessEntry`, `DeleteAccessEntry`, `DescribeAccessEntry`, `UpdateAccessEntry`, `ListAccessEntries`, `AssociateAccessPolicy`, `DisassociateAccessPolicy`, `ListAssociatedAccessPolicies`. These are already in clusterawsadm's CloudFormation; Palette's cloud-account docs must add them. Add `eks:ListAccessPolicies` for the UI dropdown. |
| Fork drift | `updateAccessEntry` matches upstream #6007. Gaps A, B, C, D and E are generic and can be sent upstream. |
| Generated files | Two CRD YAMLs (description text only), via `make generate-go-apis`. |

---

## 11. Out of scope

- Access entries for self-managed node roles in `api` mode (upstream limitation; not used by Palette).
- Removing the `aws-auth` writer in `api` mode.
- Migrating pack `iamAuthenticatorConfig` mappings to access entries (the epic keeps the pack as the source of truth).
- Fixing the pre-existing failing tests and lint findings in untouched code.
- Hubble / UI / TF / Crossplane / docs implementation.

---

## 12. Decisions needed

| ID | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | PCP-7715 scope | A only (bot design) vs A–E + #6007 (this doc) | A–E + #6007; each item maps to an epic requirement, except E, which is an efficiency improvement |
| D2 | Unmanaged entries in spec | Additive-only policies (implemented) vs full management | Additive-only, to avoid lockout |
| D3 | Who guarantees R5 | Palette adds the cloud-account entry (this doc) vs Palette rejects that ARN and relies on creator-admin (bot design) | Palette adds the entry; it also covers brownfield mode switches (S3) and static-key accounts |
| D4 | Default mode for new clusters | `nil` / `config_map` (bot design) vs `api_and_config_map` (PCP-6715, closed) | Confirm with the epic owner |
| D5 | Spikes S1–S3 | Before or after merge | Before release; S2 can tighten the webhook later |

---

## 13. References

- AWS: [Create access entries](https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html),
  [CreateAccessEntry](https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateAccessEntry.html),
  [AssociateAccessPolicy](https://docs.aws.amazon.com/eks/latest/APIReference/API_AssociateAccessPolicy.html),
  [aws-auth deprecation](https://docs.aws.amazon.com/eks/latest/userguide/auth-configmap.html)
- Upstream CAPA: #5583 (access entries), #6003 (recreate loop), #6007 (fix)
- Palette bot design: `origin/claude/PCP-4870-design:docs/design/PCP-4870.md` (`6a3ed8398`). Its CAPA pin
  `v2.12.1-beta1.0.20260909102119-d62957ae0251` is out of date; HEAD pins `v2.12.1-spectro-4.10.2`.
