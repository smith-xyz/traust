# Per-technology review checks

Read the section for each technology the checkout uses. Every run verifies
the same questions, so two audits of the same code ask the same things.

**How to use the checks.** Each check is a question you answer from code,
with the CWE a confirmed finding files under and the standard requirement
it verifies: an OWASP ASVS 5.0 section and, for operator checks that one
fits, the OWASP Kubernetes Top 10 ID from this skill's K01–K10 table. A check is never a
conclusion:
- **Confirm it with evidence:** the deterministic fact named in the
  Evidence column where one exists, otherwise a cited `file:line` or a
  traced data flow.
- **No evidence either way** is a `coverage_gaps` entry, not a negative.
- **Checks marked *judgement*** have no deterministic answer. Say how you
  decided.

These checks are Traust's own wording. Standards are cited by ID only.

## Selecting sections

| Section | Applies when |
|---|---|
| Kubernetes operators | `go.mod` requires `sigs.k8s.io/controller-runtime` or `k8s.io/client-go`, the code implements a `Reconcile` method, or the tree carries `+kubebuilder` markers |
| gRPC | `go.mod` requires `google.golang.org/grpc` and the code calls `grpc.NewServer`, or traust-core's gRPC service x interceptor matrix (`code_facts.grpc_guards`, traust-core#183) reports servers or services |

A checkout can select both. Record which sections ran (see Recording).

## Kubernetes operators

The operator reconciles custom resources (CRs) that tenants or users create,
using a service account that is usually far more privileged than they are.
Treat every CR field as untrusted input and the operator as a confused
deputy waiting to happen. `/operator-priv-profile` reviews the RBAC the
operator holds. These checks review what its code does with it.

A CR's author is whoever can create it. For a namespaced CR, that is anyone
with create rights in the namespace, often a tenant; for a cluster-scoped
CR, a cluster administrator. A finding needs the CR to be writable by
someone less privileged than the operator. Say which case applies.

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| OP.1 | Does a CR spec field reach a command, file path, URL, template or query without validation (for example `spec.url` fetched by the operator, `spec.path` joined into a host path)? | CWE-20 | ASVS V2.2 | traced flow from the CR read (`r.Get(ctx, req.NamespacedName, &obj)`) to the sink, `file:line` at both ends |
| OP.2 | Does the operator build a Pod, Deployment or Job whose privilege comes from the CR: `privileged`, host namespaces, `hostPath`, added capabilities, a user-chosen image or service account? Not applicable when the operator creates no workloads; record that as the negative. | CWE-250 | ASVS V8.2; K01 | the workload template and the CR fields that feed it |
| OP.3 | Can a CR in one namespace make the operator read or write an object in another (`spec.secretRef.namespace`, a cross-namespace owner reference, a cluster-scoped target named by the CR)? | CWE-441 | ASVS V4.1; K02 | the client call whose namespace or name comes from the CR |
| OP.4 | Does a CR choose which objects the operator deletes, patches or adopts (a label selector or name taken from the spec) so that one tenant's CR can act on another's objects? | CWE-639 | ASVS V8.2; K02 | the selector or name in the delete, patch or ownership call |
| OP.5 | Does Secret data the operator reads reach a place it isn't meant for? Its intended targets are the Secret it generates and any external store the CR names. Credential Secrets it reads to authenticate (store or provider credentials) have no intended target outside the operator. Neither may reach CR status, events, logs, ConfigMaps or annotations, including through an error message (`err.Error()` passed to an event or status condition). | CWE-532 / CWE-200 | ASVS V16.2 / ASVS V14.2; K03 | the read, and each write or error path that carries it, `file:line` |
| OP.6 | Do validating or mutating webhook handlers allow the request on an error path: an `Allowed` response after a decode or lookup error, or a controller-runtime `CustomValidator` that returns a nil error when it couldn't evaluate the object? | CWE-755 | ASVS V16.5; K04 | the handler's error branches |
| OP.7 | Is a webhook that enforces a security rule registered with `failurePolicy: Ignore`, or scoped (namespace or object selector) so that a user can opt their objects out? | CWE-1188 | ASVS V13.2; K04 | the webhook configuration: kubebuilder markers, shipped manifests, or Helm templates and their default values |
| OP.8 | Does the CRD schema (or the controller) bound security-relevant fields: enums, patterns, lengths, immutability after creation? | CWE-20 | ASVS V2.2; K04 | the CRD's OpenAPI schema and `+kubebuilder:validation` markers; *judgement* when validation lives only in code |
| OP.9 | Is the manager's metrics, health or pprof endpoint served without authentication or on all interfaces (`metricsserver` without secure serving, `--metrics-bind-address=:8080`, `pprof` handlers registered)? | CWE-306 | ASVS V6.3; K05 | the manager options, the flag defaults and the Helm chart's default values, and any registered debug handlers |
| OP.10 | Are the webhook and API servers the operator runs served over TLS only? Whether a webhook must also authenticate its caller is a *judgement*, answered only when a client other than the API server can reach it. | CWE-319 | ASVS V12.2; K06 | the webhook server options and certificate wiring |
| OP.11 | Does the operator deploy images by tag, from the CR or from an environment variable, without a digest or a registry allow-list? Not applicable when it deploys no images. | CWE-494 | ASVS V15.2; K07 | the image reference in the workload template and where it comes from |
| OP.12 | Does the operator watch or cache cluster-wide (all namespaces, cluster-scoped informers) when its function needs one namespace? | CWE-250 | ASVS V8.2; K02 | the manager's cache and namespace options, against the RBAC it holds (`/operator-priv-profile`'s profile when it ran, otherwise the shipped Role and ClusterRole manifests) |
| OP.13 | Are tokens or credentials the operator mints or projects (service account tokens, cloud credentials) scoped to the CR's tenant and audience, and revoked or expired when the CR is deleted? | CWE-269 / CWE-613 | ASVS V8.2 / ASVS V7.3; K02 / K08 | the token request or credential write, and the finalizer. With many issuance sites (one per provider), sample up to three and record the rest as a coverage gap; *judgement* |

## gRPC

The service x interceptor matrix (traust-core's `code_facts.grpc_guards`,
traust-core#183) gives:
- `servers`: each `grpc.NewServer` call with its `interceptors` (each
  marked `guard` when auth-shaped), `unary_guarded`, `stream_guarded` and
  `credentials`;
- `services`: each registered service with its `methods` and `streams`,
  `judgement_required` and `judgement_reasons`;
- `exposures`: reflection, health, channelz and admin services;
- `method_references`: full method names (`/pkg.Service/Method`) in server
  code;
- `coverage_gaps`.

An empty list means the enumerator found none on the servers it resolved.
A guard-named interceptor is still read to confirm that it rejects. The
matrix doesn't list other server options (message sizes, keepalive), so
read those from the `grpc.NewServer` call. Until its `traust adapters`
command is on this branch, gather the same facts from the `grpc.NewServer`
and `Register…Server` calls, and cite the lines.

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| GR.1 | Does every service on a server reachable from outside the pod enforce authentication, in an interceptor or in each method? | CWE-306 | ASVS V6.3 | the servers' `unary_guarded` / `stream_guarded` and their `guard` interceptors (read to confirm they reject); the services' `judgement_required` and `judgement_reasons` |
| GR.2 | When the auth interceptor is unary-only, do the service's streams authenticate some other way? | CWE-306 | ASVS V6.3 | a server with `stream_guarded: false` serving a service that has `streams` |
| GR.3 | Once a caller is authenticated, are methods authorized individually (admin or write methods restricted) rather than all-or-nothing? Authorization delegated to another system (Kubernetes RBAC through a SubjectAccessReview, a policy engine) is a negative when it runs for every method; cite the call. | CWE-862 | ASVS V8.3 | the interceptor or handler code that branches on `info.FullMethod` or calls the delegate; the matrix's `method_references`; *judgement* |
| GR.4 | Do auth exemption lists match full method names exactly, rather than by prefix, `strings.Contains` or a service-wide wildcard that also exempts other methods? | CWE-288 | ASVS V6.3 | the matrix's `method_references` and the comparison at each; with none, say no exemption list exists and cite the auth interceptor |
| GR.5 | Are reflection, channelz or admin services registered on a server that is reachable from outside the pod or unauthenticated? | CWE-200 | ASVS V14.2 | the matrix's `exposures` (`guarded` is false, true, or null when the server is built elsewhere) |
| GR.6 | Does a server listening beyond loopback use TLS, whether set as server credentials or on its listener (`tls.NewListener`, or a TLS `http.Server` that multiplexes gRPC)? | CWE-319 | ASVS V12.2 | the server's `credentials`; when empty, the `net.Listener` and `tls.Config` it is served on, and the default of any flag that turns TLS off |
| GR.7 | Are authorization decisions based on caller-supplied metadata (`x-user`, `x-forwarded-*`, a tenant header) that nothing verifies? | CWE-807 | ASVS V2.3 | the `metadata.FromIncomingContext` reads that feed a decision |
| GR.8 | Is a gRPC-gateway registered in process with `Register…HandlerServer`? That variant calls the service directly and skips the gRPC interceptors, authentication included; `Register…HandlerFromEndpoint` dials the server and goes through them. For the dialling variant, check the dial's TLS settings (no `InsecureSkipVerify` beyond loopback). | CWE-288 | ASVS V6.3 | the gateway registration (the matrix leaves gateway registrations out of `services`) and where the gateway's HTTP server applies auth |
| GR.9 | Are message size, concurrent stream and keepalive limits set and sized for untrusted callers (`grpc.MaxRecvMsgSize`, `grpc.MaxConcurrentStreams`, `keepalive.EnforcementPolicy`)? The default receive limit is 4 MiB; a much larger limit needs a reason. | CWE-770 | ASVS V2.4 | the `grpc.NewServer` options, read directly |
| GR.10 | Do status errors returned to callers carry internal errors, stack traces or backend messages (`status.Error(codes.Internal, err.Error())`)? | CWE-209 | ASVS V16.5 | the handlers' error returns and any error-translation or panic-recovery interceptor |
| GR.11 | Where client certificates are the authentication, does the server's TLS configuration require and verify them (`tls.RequireAndVerifyClientCert` with a client CA)? Not applicable when callers authenticate with tokens. | CWE-295 | ASVS V12.3 | the `tls.Config` behind the server's credentials or listener |

## Recording the review

- **Coverage:** in `metadata.additional.deterministic_steps`, record
  `"framework-checks": "ran: <sections>"` (for example
  `"ran: operators, grpc"`), or `"ran: none"` when no section applies.
- **A check you couldn't answer** is a `coverage_gaps` entry:
  `{"tool": "framework-checks", "system": "<check ID>", "reason": "…"}`.
- **Findings** carry:
  - the check's CWE in `cwes`;
  - its ASVS section in `asvs_references`.

  Name the check ID, and for operators the K-ID, in the `description`, for
  example "check OP.3, K02".
- **`/vuln-scan` findings** (the `vuln-findings` format) name the check ID,
  the ASVS section and, for operators, the K-ID in the `description`.
- **Negative results** state the check ID, what was examined and the
  evidence, for example "GR.1: every service on `cmd/server/main.go:42` is
  behind `authUnary`, and `authUnary` rejects a missing token at
  `internal/auth/grpc.go:31`".
