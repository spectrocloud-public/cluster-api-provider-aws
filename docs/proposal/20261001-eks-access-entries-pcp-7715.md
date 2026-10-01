# EKS access entries: CAPA and Palette design

| | |
|---|---|
| Epic | [PCP-4870](https://spectrocloud.atlassian.net/browse/PCP-4870) — Support EKS access entries (EKS API) IAM access mode |
| Task | [PCP-7715](https://spectrocloud.atlassian.net/browse/PCP-7715) — CAPA implementation to support IAM access entries |
| Upstream | [#5583](https://github.com/kubernetes-sigs/cluster-api-provider-aws/pull/5583) (access entries), [#6003](https://github.com/kubernetes-sigs/cluster-api-provider-aws/issues/6003) / [#6007](https://github.com/kubernetes-sigs/cluster-api-provider-aws/pull/6007) (recreate loop) |
| Status | CAPA: implemented. Palette: design. |

## 1. Summary

AWS has deprecated the `aws-auth` ConfigMap for granting IAM principals access to EKS, in favour of **access entries**.
Palette only supports the ConfigMap today, configured through the EKS pack (`managedControlPlane.iamAuthenticatorConfig`).

- **CAPA already has access entries.** Upstream #5583 is in our fork (`v2.12.1-spectro-4.10.2`). Palette already pins
  that tag, and its vendored CRDs contain `accessConfig` and `accessEntries`. No port or version bump is needed.
- **The upstream code has gaps that break Palette's requirements.** PCP-7715 fixes them (§4). The fixes are generic,
  contain no Palette logic, and can be sent upstream.
- **Palette does not use the fields yet.** That is the follow-up work under the epic (§5).

## 2. Background

**Translation step.** On every request, EKS turns the caller's IAM ARN (proven with an STS-signed token) into a
Kubernetes user and groups; Kubernetes RBAC then authorizes it. The two mechanisms for that translation:

| | `aws-auth` ConfigMap | Access entries |
|---|---|---|
| Lives in | `kube-system` inside the cluster | EKS control plane |
| Managed by | Editing YAML | `Create/Update/DeleteAccessEntry` |
| Permissions | Your own RBAC | Optional AWS-managed access policies, scoped to the `cluster` or to `namespace`s (wildcards allowed) |
| Audit / recovery | None / not if the cluster is broken | CloudTrail / works when the cluster is broken |

**Authentication modes.** `CONFIG_MAP` (ConfigMap only), `API_AND_CONFIG_MAP` (both), `API` (entries only).
- Modes can only move towards `API`, never back.
- The AWS CLI docs show `CONFIG_MAP → API` as a single step ("replace `API_AND_CONFIG_MAP` with `API`").
- In `API_AND_CONFIG_MAP`, **an access entry takes precedence over a ConfigMap mapping for the same principal**.
- Minimum platform versions: `1.28 eks.6`, `1.29 eks.1`, `1.30 eks.2`. Later Kubernetes versions are all supported.

**Entry types.** Only `STANDARD` (the default) can have `kubernetesGroups` or access policies. `EC2_LINUX`,
`EC2_WINDOWS`, `FARGATE_LINUX`, `HYBRID_LINUX`, `HYPERPOD_LINUX` and `EC2` are node identities (EKS user guide,
*Create access entries*).

**Entries EKS creates itself.**
- **Cluster creator admin.** With `bootstrapClusterCreatorAdminPermissions: true`, EKS creates an admin entry for
  the cluster creator. For Palette that is the cloud-account principal. EKS also creates this entry when access
  entries are enabled on an existing ConfigMap cluster.
- **Managed node groups and Fargate.** EKS creates their entries. Palette only uses these pool types, so no node
  entries are needed.
- **Generated username.** If `username` is unset, EKS generates one. `DescribeAccessEntry` returns it.

## 3. Requirements

| # | Requirement (PCP-4870) |
|---|---|
| R1 | Choose `API` or `API_AND_CONFIG_MAP` on day 0 and day 2 |
| R2 | Pack ConfigMap IAM configuration keeps working |
| R3 | Entries `[type, principal, username, groups]` on day 0 and day 2 |
| R4 | One or more access policies on `STANDARD` entries, scoped to the cluster or to namespaces (with wildcards) |
| R5 | The Palette cloud-account IAM principal is cluster admin |
| R6 | Day-2 changes don't repave nodes |
| R7 | Palette and Vertex; UI, API, Terraform, Crossplane; documentation |

Epic open questions:
- **Worker-node entries?** Not needed. Palette uses managed node groups and Fargate, and EKS creates their entries.
- **Non-admin bootstrap principal?** Not feasible. CAPA's kubeconfig, which Palette also uses, authenticates as that
  principal.

## 4. CAPA changes (PCP-7715)

### 4.1 Current behaviour

`ReconcileControlPlane` (`pkg/cloud/services/eks/cluster.go`) calls `reconcileAccessConfig`, which runs
`UpdateClusterConfig` for the mode. It then calls `reconcileAccessEntries` (`accessentry.go`), followed by logging,
encryption, tags and OIDC. A failure in access entries stops those later steps.

An entry is **managed** when it carries the `kubernetes.io/cluster/<name>=owned` tag that CAPA adds on create. Only
managed entries are updated or deleted.

### 4.2 Changes

| ID | Problem | Change |
|---|---|---|
| **A** | An empty `accessEntries` list skipped reconciliation, so removing the last entry never revoked it. | The decision depends on the mode only. An empty list deletes all managed entries. |
| **B** | A principal that exists without the CAPA tag (typically the creator entry, i.e. the cloud-account role) hit `CreateAccessEntry` → `ResourceInUseException` on every pass, blocking later reconcile steps. A failed `DescribeAccessEntry` was skipped, making managed entries look unmanaged. | List every entry with a managed flag; return describe errors. An **unmanaged entry in the spec is additive-only**: missing policies are associated, and the entry is never recreated, deleted or stripped of policies. That prevents removing the controller's own admin access. |
| **#6007** | `updateAccessEntry` recreated entries when `username` was unset (EKS generates one) or `type` was empty, so access flapped on every reconcile. | Adopt upstream #6007: an empty type counts as `standard`; only a type change recreates; username and groups are updated in place; an unset username is not drift. |
| **C** | Entries were reconciled while the auth-mode update was still in progress. | Wait for `ACTIVE` (`WaitUntilClusterActive`) after a mode change. |
| **D** | The webhook only rejected groups and policies on EC2 types, and allowed duplicates. | Reject duplicate principals, and duplicate policies within an entry. Allow `kubernetesGroups` and `accessPolicies` only on `standard` entries. The service skips policies for non-standard types. API doc comments and CRD descriptions updated (`make generate-go-apis`). |
| **E** | Every policy was re-associated on every reconcile. | Associate only when a policy is missing or its scope changed (namespace order ignored). |

### 4.3 Reconcile logic after the change

```go
if !accessEntriesEnabled(spec.AccessConfig) { return nil }      // A: mode decides, not list length

existing, err := s.getExistingAccessEntries(ctx)                // B: principal -> managed?, describe errors returned
for _, entry := range spec.AccessEntries {
	managed, exists := existing[entry.PrincipalARN]
	switch {
	case !exists: s.createAccessEntry(ctx, entry)               // tagged as owned
	case managed: s.updateAccessEntry(ctx, entry)               // #6007 rules, full policy reconcile
	default:      s.associateAccessPolicies(ctx, entry)         // B: additive only
	}
	delete(existing, entry.PrincipalARN)
}
for principal, managed := range existing {
	if managed { s.deleteAccessEntry(ctx, principal) }         // never delete unmanaged entries
}
```

For an unmanaged entry, a Warning event (`AccessEntryNotManaged`) is emitted **only when the spec sets fields that
are not applied** (`username`, `kubernetesGroups`, or a non-standard `type`). The expected case, a principal plus
policies (Palette's cloud-account entry), is logged at debug level, so it doesn't create permanent event noise.

| Entry | Action |
|---|---|
| Not in EKS | Create (tagged), then reconcile policies |
| Managed | Recreate on type change; update username and groups in place; associate missing or changed policies; disassociate extras |
| Unmanaged, in spec | Associate missing or changed policies only |
| Unmanaged, not in spec | Ignore |
| Managed, not in spec | Delete |

### 4.4 Not changed

- No new API fields, no CRD schema changes, and no `v1beta1` conversion work.
- Direct `config_map → api` is still allowed. The AWS docs suggest it's valid; to be confirmed on a cluster (§7).
- `aws-auth` is still written in every mode (it's ignored in `api` mode).
- No entries for self-managed node roles (an upstream limitation; Palette doesn't use them).
- No "add my own identity as admin" in CAPA; that belongs to Palette.

### 4.5 Files

| File | Change |
|---|---|
| `pkg/cloud/services/eks/accessentry.go` | A, B, #6007, D (service side), E, warning behaviour |
| `pkg/cloud/services/eks/cluster.go` | C |
| `controlplane/eks/webhooks/awsmanagedcontrolplane_webhook.go` | D |
| `controlplane/eks/api/v1beta2/awsmanagedcontrolplane_types.go` + 2 generated CRD YAMLs | Doc comments / descriptions |
| `*_test.go` (accessentry, cluster, webhook) | Tests (§6) |

## 5. Palette design

### 5.1 Where the setting lives

It is a **cloud-config field** (`EksClusterConfig`), not a pack value, as the epic asks. `nil` keeps today's
behaviour: `config_map` plus the pack's `aws-auth`. The first release is **opt-in**; the default stays `nil`.

### 5.2 Types (`api/v1` and `api/v1alpha1` `EksClusterConfig`)

```go
// +optional
AccessConfig *EksAccessConfig `json:"accessConfig,omitempty"`

type EksAccessConfig struct {
	// +kubebuilder:validation:Enum=api;api_and_config_map
	AuthenticationMode string           `json:"authenticationMode"`
	AccessEntries      []EksAccessEntry `json:"accessEntries,omitempty"`
}

type EksAccessEntry struct {
	PrincipalARN     string            `json:"principalARN"`
	Type             string            `json:"type,omitempty"` // enum as CAPA; default standard
	Username         string            `json:"username,omitempty"`
	KubernetesGroups []string          `json:"kubernetesGroups,omitempty"`
	AccessPolicies   []EksAccessPolicy `json:"accessPolicies,omitempty"` // max 20
}

type EksAccessPolicy struct {
	PolicyARN   string         `json:"policyARN"`
	AccessScope EksAccessScope `json:"accessScope"` // type cluster|namespace (default cluster), namespaces
}
```

- Palette defines its own types rather than embedding CAPA's. `ally` compiles Palette's API against an older CAPA pin
  that lacks `AccessEntry`, and embedding would also tie Palette's public API to CAPA.
- Field names match CAPA, but the shape differs: entries are nested under `EksAccessConfig` in Palette and top-level
  in CAPA. Mapping is therefore a **structural mapping**, not a copy.
- v1alpha1 ↔ v1 conversion is a JSON round-trip, so `make generate manifests` is the only step needed.

### 5.3 Builder (`getDesiredManagedControlPlane`, `pkg/provider/aws/aws_managed.go`)

```go
if cfg := clusterConfig.AccessConfig; cfg != nil {
	mcp.Spec.AccessConfig = &ekscontrolplanev1.AccessConfig{
		AuthenticationMode:                      ekscontrolplanev1.EKSAuthenticationMode(cfg.AuthenticationMode),
		BootstrapClusterCreatorAdminPermissions: ptr.To(true),
	}
	mcp.Spec.AccessEntries = append(toCAPAAccessEntries(cfg.AccessEntries), cloudAccountAdminEntry(account))
}
```

1. **Set the CRD defaults explicitly** (`type: standard`, `accessScope.type: cluster`,
   `bootstrapClusterCreatorAdminPermissions: true`). Otherwise the stored object always differs from desired and
   Palette updates it on every loop.
2. **Never send `AccessConfig: nil` once it has been set.** The CAPA webhook rejects removing it.
3. **Cloud-account admin entry (R5):** a `standard` entry with `AmazonEKSClusterAdminPolicy`, cluster scope, and no
   `username` or `groups`. CAPA treats the EKS-created creator entry as unmanaged and only adds the policy.
   - **ARN normalization.** Entries use IAM ARNs, so compare and create with the IAM role or user ARN, exact string:

     | Account type | Source | Normalization |
     |---|---|---|
     | STS | `Sts.Arn` | Already an IAM role ARN (used as `AWSClusterRoleIdentity.RoleArn`) |
     | Pod identity | `IamRoleArn` | Already an IAM role ARN |
     | Static keys | STS `GetCallerIdentity` | IAM user ARN as-is. With a session token the result is `arn:<partition>:sts::<acct>:assumed-role/<role>/<session>`: convert it to `arn:<partition>:iam::<acct>:role/<path><role>`, resolving the path with `iam:GetRole`. |

   - **Rotation.** When the cloud account changes on day 2, the new principal's entry is created. The old creator
     entry is unmanaged, so CAPA never removes it, and the old principal stays admin. Palette must handle revocation
     explicitly: either document a manual `aws eks delete-access-entry`, or run a one-off cleanup when the account
     changes. To decide (D6).
4. **Pack coexistence (R2).** Emit a Warning event when:
   - the mode is `api` and the pack has `mapRoles` / `mapUsers` (they're ignored), or
   - an access entry names a principal that is also in the pack mappings (the access entry wins).

### 5.4 Day 2

- Add `"AccessConfig.AuthenticationMode"` and `"AccessEntries"` to the ungated `allowedUpgradePaths` in
  `shouldUpgradeMCP`. These are cloud-config fields, like `EndpointAccess`.
- Copy both fields in the update block of `CreateUpdateManagedControlPlane`, keeping the existing
  `bootstrapClusterCreatorAdminPermissions`, which is only used at create time.
- Changes to the AMCP alone don't touch `AWSManagedMachinePool`, so there's no node repave (R6, to verify in E2E).
- The `overrideClusterAPIConfig` passthrough is applied last and replaces arrays whole, so it wins over the typed
  fields. Document this.

### 5.5 Palette webhook

Validate on submit:
- The mode is one-way, and `accessConfig` cannot be removed once set.
- No duplicate principals, and no duplicate policies within an entry.
- Groups and policies only on `standard` entries.
- `namespaces` only with `namespace` scope.
- The cloud-account principal is rejected, because Palette adds it.

### 5.6 Other touch points

| Area | Change |
|---|---|
| EKS adoption (`pkg/eksadoption`) | Map the discovered mode and entries. Without this, adopted `api`-mode clusters still work (CAPA skips a nil `accessConfig`), but Palette shows the wrong state. Same release if adoption is in scope. |
| `ally` converter | Map the hapi fields; bump the `palette` and `hapi` versions. The CAPA pin stays unchanged. |
| hapi, UI, Terraform, Crossplane, docs | Fields with the §5.2 shape, the UI section, and IAM permissions in the docs (§8). |
| Pivot, Vertex | No change (pivot does a DeepCopy; Vertex has no separate EKS code). |

**Merge order:** CAPA (this PR) → Palette (types, webhook, provider, go.mod) → hapi/UI/TF/Crossplane (in parallel) →
ally. Palette has no effect until ally ships.

## 6. Test plan

**CAPA unit tests (implemented; gomock + Gomega, table-driven):**

| Area | Cases |
|---|---|
| `reconcileAccessEntries` | empty list deletes managed and keeps unmanaged; `config_map` makes no calls; an unmanaged entry only gets policies added; an unmanaged entry without policies is unchanged; describe and list errors are returned |
| `updateAccessEntry` | unset username and unset type cause no recreate; a username change or addition updates in place; a type change recreates |
| Policies | unchanged, reordered namespaces, changed namespaces, cluster ↔ namespace, non-standard types skipped; `accessScopeEqual` |
| Warning behaviour | `unmanagedAccessEntryIgnoredFields` reports only fields that are set |
| `reconcileAccessConfig` | waits for `ACTIVE` after a mode change; a wait timeout returns an error |
| Webhook | duplicate principal and policy; groups and policies rejected on fargate and hybrid; unset type accepted |

The changed packages pass `go test`, `go vet` and golangci-lint (repo pin). The full suite has a few failures that
also fail on the unchanged base commit and are unrelated (`TestUpdateTagsForEKSManagedSecurityGroup`,
`TestFuzzyConversion`, `TestNodeadmConfigReconciler_*`).

**On a real cluster (Palette and Vertex; commercial and GovCloud):**
1. Day 0 `api_and_config_map` with a standard entry and a namespace policy (`dev-*`).
2. Day 2: add, update, and remove all entries.
3. Day 2: `config_map → api_and_config_map` on an existing cluster. Check that the creator entry exists and pack
   `aws-auth` users still work.
4. Direct `config_map → api` (confirm AWS accepts it).
5. Entry calls during the mode update (confirms whether C is required; it's safe either way).
6. The cloud-account entry keeps `AmazonEKSClusterAdminPolicy` throughout.
7. After every step, `aws eks list-access-entries` matches the spec, and node instance IDs are unchanged (no repave).

## 7. Edge cases

| Scenario | Behaviour |
|---|---|
| No `accessConfig` (existing clusters) | Unchanged; no access-entry calls |
| Last entry removed | Deleted (A) |
| Creator or cloud-account principal in spec | Adopted additively; admin policy never removed; no warning unless ignored fields are set (B) |
| Username or groups set on an unmanaged entry | Not applied; Warning event (B) |
| Manual or node entries | Never touched (B) |
| Transient describe error | Reconcile error and retry (B) |
| Unset `username` or `type` | No drift, no recreate (#6007) |
| Username changed or added | In-place update (#6007) |
| Type changed | Recreate (type is immutable) |
| Mode change plus entries in one save | Wait for `ACTIVE`, then entries in the same pass (C) |
| Duplicates; groups or policies on non-standard types | Rejected by the webhook (D) |
| Policy unchanged or namespaces reordered | No API call (E) |
| Scope or namespaces changed | Re-associated (E) |
| Mode downgrade or removing `accessConfig` | Rejected by the webhook |
| `config_map → api` directly | Allowed (to be confirmed on a cluster) |
| Same principal in an access entry and pack `mapRoles` | The access entry wins; Palette warns |
| Pack mappings with mode `api` | Ignored by EKS; Palette warns |
| Cloud-account rotation | Old principal stays admin until explicitly revoked (D6) |
| Platform version below the minimum | `UpdateClusterConfig` fails; error on the control plane |
| Missing IAM permissions | AccessDenied in reconcile (§8) |

## 8. Impacts

| Area | Impact |
|---|---|
| Compatibility | Clusters without `accessConfig` are unchanged. Clusters that already use `accessConfig` through the passthrough get the fixes: an empty list now revokes access, and the recreate loop stops. |
| Behaviour | A username change is an in-place update. Removing `username` keeps the EKS value. |
| AWS API usage | `api` modes list entries and describe each one (including node and Fargate entries) on every reconcile. Unchanged policies are no longer re-associated. Watch the call volume on large fleets. |
| Reconcile time | A mode change holds the worker until `ACTIVE`, as other CAPA waits do. |
| IAM permissions | `eks:CreateAccessEntry`, `DeleteAccessEntry`, `DescribeAccessEntry`, `UpdateAccessEntry`, `ListAccessEntries`, `AssociateAccessPolicy`, `DisassociateAccessPolicy`, `ListAssociatedAccessPolicies` (plus `ListAccessPolicies` for the UI dropdown). Add them to the Palette cloud-account docs. |
| Fork drift | `updateAccessEntry` matches upstream #6007; the other fixes are generic and can be sent upstream. |

## 9. Decisions

| ID | Decision | Recommendation |
|---|---|---|
| D1 | PCP-7715 scope | A–E + #6007 |
| D2 | Unmanaged entries in spec | Additive-only |
| D3 | How R5 is met | Palette adds the cloud-account entry, with ARN normalization |
| D4 | Default mode for new clusters | Opt-in (`nil`) for the first release |
| D5 | Open AWS behaviour | Confirm `config_map → api` and the in-progress entry calls on a cluster before release |
| D6 | Cloud-account rotation | Choose documented manual revoke or automatic cleanup before Palette implements |

## 10. References

- AWS EKS user guide: [Access entries](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html),
  [Change authentication mode](https://docs.aws.amazon.com/eks/latest/userguide/setting-up-access-entries.html),
  [Create access entries](https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html),
  [Migrating aws-auth entries](https://docs.aws.amazon.com/eks/latest/userguide/migrating-access-entries.html)
- AWS EKS API: [CreateAccessEntry](https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateAccessEntry.html),
  [AssociateAccessPolicy](https://docs.aws.amazon.com/eks/latest/APIReference/API_AssociateAccessPolicy.html)
- Upstream CAPA: #5583, #6003, #6007
