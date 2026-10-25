# Components — the repositories this harness is built from

The harness is **not one repository**. Its ecosystem includes six code components
plus three data repositories. This page maps current ownership and dependencies,
the migration toward shared core services, how commits are pinned, and **which
repo to change for a given fix**.

If you only want to install and run, [setup.md](setup.md) is enough.
Read this before changing a schema, an enum, the fingerprint recipe, or
anything under `traust_engine`, `traust_ledger`, or `traust_core`.

---

## 1. The stack

| Component | Lang | Responsibility |
|---|---|---|
| `traust` | Python | Security skills (`harnessing/`), prompts, slash commands, agent-facing CLIs (`src/traust/`), workflow policy, docs, and gates |
| [traust-core](https://github.com/traust-security/traust-core) | Python | Shared platform API under `traust_core.v1`: domain models, repositories, services, artifact publishing, configuration/context, rendering, and provider interfaces; adoption in progress |
| `traust-engine` | Python | Existing deterministic processing: scanner adapters, corpus and portfolio processing, metrics, reporting (including SARIF), validation, compliance, toolchain integration, and the ledger gateway |
| `traust-ledger` | Python | Finding identity, event history, Merkle integrity, signing, verification, and the current client, CLI, and REST service entry points |
| `traust-contracts` | Python/data | Canonical artifact/config schemas, controlled vocabularies, shared bindings, and database DDL |
| `traust-sdk` | Go | Typed access to contracts, storage, ledger integration, and skill execution for non-Python consumers |

### Current dependencies

The harness declares direct dependencies on `traust-engine`, `traust-ledger`,
and `traust-contracts`. Engine also depends on ledger and contracts; ledger
depends on contracts. The direct ledger dependency covers existing harness
imports that have not moved behind the engine's ledger gateway.

Core is a separate package that pins contracts. The harness, engine, and ledger
do **not yet declare a dependency on core**. Their installed behavior is defined
by their manifests and lockfiles, not by the presence of a sibling core checkout.

**`traust-sdk` is not a dependency of the harness.** It is a sibling consumer:
its generator pins contracts, and its APIs integrate with storage, the ledger,
and skill execution. Nothing in this repository imports it.

### Core migration boundary

Contracts defines the canonical data shapes and database structure. Core
provides typed access, persistence, and shared platform behavior over those
contracts. The intended direction is for engine execution and CLI adapters to
call shared core services while security workflow policy remains in `traust`.
This is a migration direction, not the current dependency graph.

Core's repositories are implemented, but its domain services are mostly stubs.
Consult the core [implementation status](https://github.com/traust-security/traust-core#domain-services-stubs)
before moving a caller; existing functionality remains with its current owner
until a working replacement and its callers land together. Do not create a
second implementation in the harness while migrating shared behavior.

The intended core REST API route for the Go SDK and other non-Python consumers
is planned, not an available integration. It is distinct from the existing
traust-ledger REST service.

### Data repositories (not components)

`setup.md` also uses the word "sibling" for these, in a different sense — its
clone list is four entries because it counts `traust` itself. They
hold content, not code, are not pip dependencies, and are referenced by relative
path, not imported:

| Repo | Holds |
|---|---|
| `analysis-results` | Audit reports, disposition ledgers, triage, threat models — the corpus |
| `<inputs-inventory>` (name is the deployment's) | Scope declarations, repo rosters, service inventories |
| `progress-tracker` | Plans, dashboards, metrics, gap assessments |

---

## 2. Which repo do I change?

The most common mistake is editing the wrong layer — usually adding a schema
field to the harness, where it has no effect, because the validator loads
schemas from the **installed contracts package** (`traust_contracts`),
not from this repo.

| I want to… | Repo | Note |
|---|---|---|
| Add or edit a skill, prompt, slash command, or security workflow policy | `traust` | Keep shared domain behavior out of pack policy |
| Change shared platform models, persistence, providers, or core services | `traust-core` | Check implementation status and migrate callers with working replacements |
| Add a field to an artifact schema | `traust-contracts` | Update affected producers and consumers before advancing their pins (§4) |
| Add an enum value | `traust-contracts` | Update canonical definitions and bindings using that repo's checks |
| Change the database structure | `traust-contracts` | Coordinate core repositories and existing SQL consumers with the selected DDL revision |
| Change the current finding fingerprint | `traust-ledger` (`_internal/identity.py`) | One implementation only; update `ALGO_VERSION` and its regression fixtures (§5) |
| Change Merkle/stamping/signing behavior | `traust-ledger` (`integrity/`) | See [signing.md](signing.md) |
| Add or fix an existing scanner adapter | `traust-engine` (`adapters/`) | Adapter results must satisfy the installed contracts schema |
| Change existing dashboards, SARIF export, or corpus resolution | `traust-engine` | Current modules remain authoritative until their core-backed replacements land |
| Change what a Go consumer sees | `traust-sdk` | Also update contracts when the data shape changes; do not assume the planned core REST route exists |

---

## 3. Version pinning

Python consumers select git commits with `rev` in `[tool.uv.sources]`.
`dependencies` carries bare package names; the commit pin selects the code,
and `uv.lock` records the resolved dependency set. Do not copy live pins into
documentation. The harness declares these three code dependencies:

```toml
dependencies = [
    "traust-engine",
    "traust-ledger",
    "traust-contracts",
]

[tool.uv.sources]
traust-engine = { git = "<forge>/traust-engine.git", rev = "<commit-sha>" }
traust-ledger = { git = "<forge>/traust-ledger.git", rev = "<commit-sha>" }
traust-contracts = { git = "<forge>/traust-contracts.git", rev = "<commit-sha>" }
```

Engine and ledger carry their own sources. Core separately pins contracts and
documents commit-based consumption rather than release tags. Adding a core
checkout beside the harness does not add it to the installed dependency graph.

### Source conflicts and compatibility

Inconsistent Git URLs or revision specifications for the same dependency can
make `uv lock` report **"conflicting URLs"**. Inspect the root project's source
overrides and the selected components' manifests, align the intended sources,
and update intermediate consumers when their implementation requires it.

A successful resolution is not proof of runtime compatibility. Schema layouts,
DDL, and APIs can change between commits; exercise affected consumers before
advancing pins. Adopting core requires working caller migrations, not merely
adding a package or changing the contracts revision.

`uv sync --locked` refuses installed dependency drift; `uv sync` restores the
dependency set selected by this project's manifest and lockfile. Read the
current sources in `pyproject.toml` and resolved commits in `uv.lock`; a sibling
checkout or its latest tag is not the installed version.

---

## 4. Release order

Update providers before their consumers, following the actual dependency graph
rather than a fixed release chain:

- Existing Python path: contracts changes may require ledger and engine changes
  before the harness can adopt them. The harness also pins all three directly.
- Core path: contracts changes may require core repository and service changes.
  The current harness does not pick these up until a caller migration adds core.
- Go path: regenerate SDK bindings and storage code against its selected
  contracts commit when those contracts change.

For an affected Python component:

1. Implement and test the change in the owning repository.
2. Merge it, then update each affected consumer's `rev` to the tested commit.
3. Run `uv lock` and `uv sync`, exercise the affected runtime path, and run that
   consumer's checks before merging its pin update.
4. Continue outward until every affected consumer has been updated.

Follow each repository's own release instructions; no tagged release is
required merely to select a merged dependency commit. This dependency workflow
does not change the harness's `VERSION`/semantic-version convention or the Go
SDK's per-language release tags. Core's evolving `traust_core.v1` namespace is
an API boundary, not a package release number or a promise that all services
are implemented.

Do not change dependency pins as part of a documentation-only core introduction.
Core adoption must also migrate callers, configuration, and persistence where
needed; its planned REST API is not a substitute for an implemented integration.

---

## 5. What crosses the boundary

Contracts defines the shared data. The selected revision determines the
physical schema and DDL layout; paths from another revision are not an API.

| Contract | Defined in | Consumed by |
|---|---|---|
| **Artifact and config schemas** | Installed `traust-contracts` schema resources | Existing Python validators, core's contracts reader, and generated SDK types/validators |
| **Enums** | Contracts' canonical enum registry and bindings | Python components and generated SDK enums |
| **Database DDL** | Contracts' authored SQL for its selected data model | Core repositories and existing SQL consumers compatible with that revision |

Update canonical definitions and regenerate or update bindings according to the
contracts repository's checks. Core supplies access and behavior; neither core
nor the harness should create a second source of truth for schemas or DDL.

### Finding identity is deliberately *not* a cross-boundary contract

**The current finding-identity recipe is owned by traust-ledger.** No consumer
or non-harness producer should implement a second fingerprint recipe; route
through the existing ledger implementation or submit unstamped. The recipe lives in
`traust_ledger/_internal/identity.py`, contract in
`traust-ledger/docs/finding-identity.md` — and its regression net sits beside it
in `traust-ledger/tests/fixtures/` (`identity-recipe-vectors.json`,
`finding-identity-vectors.json`). Those are **fixtures, not a contract**: they
exist so the one implementation cannot change by accident, especially across an
`ALGO_VERSION` bump. Changing the recipe intentionally means moving
`ALGO_VERSION` and letting the fixtures' recorded values make the move visible
rather than a silent re-baseline.

Do not reintroduce a fingerprint implementation outside `traust-ledger` — not in
the Go SDK, not in a producer. A divergent fingerprint means two systems disagree
about whether two findings are the same finding, and that compounds through
every dedupe, alias and metric downstream.

---

## See also

- [setup.md](setup.md) — cloning the workspace and `uv sync`
- [traust-core](https://github.com/traust-security/traust-core) — platform API, implementation status, and core-specific development instructions
- [architecture.md](architecture.md) — code internals within a component
- [disposition-ledger.md](disposition-ledger.md) — what `traust-ledger` is protecting
- [signing.md](signing.md) — ledger signing
