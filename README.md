# Path Diversity Fabric 1.0.0

Path Diversity Fabric is the authoritative path-independence and diversity-proof runtime of
the Distributed Fabric Infrastructure / Fabric OS stack. It answers exactly one question:

> Given two or more exact current candidate or authorized paths and an explicit diversity
> requirement, are those paths genuinely independent under the current topology and
> failure-domain evidence, which exact resources or correlated risks are shared, what
> diversity class is proven, and when must that proof be rejected, demoted, fenced,
> superseded or revalidated?

It consumes already-computed, already-authorized paths. It never discovers, computes,
optimizes or programs a route.

---

## 1. Systems boundary

Path Diversity Fabric owns: diversity policy identity and generation, diversity proof
identity and generation, exact path-set binding, pairwise and set-wise diversity
evaluation, link-disjointness proof, transit-node-disjointness proof, device-disjointness
proof, rack/pod/site diversity over authoritative placement evidence, shared-risk-group and
correlated-failure diversity, explicit endpoint-exemption semantics, exact
topology/failure-domain/Path-Authority generation binding, completeness requirements,
UNKNOWN semantics, deterministic proof classification, shared-resource explanation, proof
lifecycle and currentness, stale-proof fencing and revalidation, snapshots, diffs,
deterministic digests, persistence with conservative recovery, and distributed publication
authority with worker-incarnation fencing.

Path Diversity Fabric does not own, and never fabricates:

| Authority | Owns |
| --- | --- |
| Fabric Registry | canonical infrastructure identity |
| Fabric Topology | structural connectivity, element generations, retirement |
| Link State Fabric | dynamic link condition |
| Port Fabric | port administrative configuration |
| Fabric Capability Registry | capability truth |
| Failure Domain Registry | correlated-failure classification, placement domains, SRLG membership and coverage |
| Fabric Epoch | control-plane epoch authority |
| Path Authority | exact path legality and the authorized Path Authority generation |
| Path Planner | path candidate computation |
| Multipath Fabric | generic simultaneous-use path sets |
| Bandwidth Broker / Reservation Fabric | capacity truth |
| Adaptive Routing Fabric / Route Fabric / ECMP | adaptation, forwarding programming, weighting |

### The principle this runtime exists to enforce

Different `PathId` values do not imply independent paths. Different links do not imply
different devices. Different devices do not imply different failure domains. Different racks
do not imply different power domains without authoritative evidence.

Seven facts are therefore kept strictly separate, and no one of them is ever derived from
another:

```
PATH IDENTITIES DIFFER
LINK SETS DIFFER
NODE SETS DIFFER
DEVICE SETS DIFFER
FAILURE-DOMAIN SETS DIFFER
SHARED-RISK GROUPS DIFFER
DIVERSITY REQUIREMENT SATISFIED
FAILOVER ACTUALLY SUCCEEDS
```

The last line is not a claim this runtime makes at all. See section 14.

---

## 2. Diversity classes

Only explicit, evidence-backed classes exist:

| Class | Evidence it consumes |
| --- | --- |
| `LINK_DISJOINT` | exact canonical link sets from authoritative path structure |
| `TRANSIT_NODE_DISJOINT` | exact node sets after the policy endpoint exemption |
| `DEVICE_DISJOINT` | exact authoritative device identity sets |
| `RACK_DISJOINT` | authoritative `RACK` placement domains |
| `POD_DISJOINT` | authoritative `POD` placement domains |
| `SITE_DISJOINT` | authoritative `SITE` placement domains |
| `FAILURE_DOMAIN_DISJOINT` | authoritative correlated-failure domains under the declared relation set |
| `SHARED_RISK_GROUP_DISJOINT` | authoritative SRLG membership |

No class is inferred from another. A link-disjoint pair may still share a rack, a switch
chassis, a conduit, a power domain or a shared-risk group, and this runtime reports exactly
that instead of collapsing the classes.

Nothing is ever inferred from a name. `rack-17` is a shared rack only because Failure
Domain Registry says so about those exact entities; a link whose identifier contains
`rack17` proves nothing.

---

## 3. Endpoint exemptions

Source and destination are usually shared by a primary and a secondary path, so endpoint
semantics are policy, not an ad hoc special case. `EndpointExemption` is one of:

| Value | Meaning |
| --- | --- |
| `NONE` | endpoint nodes are ordinary nodes; sharing either fails node-disjointness |
| `SHARED_SOURCE_AND_DESTINATION` (default) | a node shared as the source of every path, or as the destination of every path, is exempt; a node shared as transit is not |
| `SHARED_SOURCE_ONLY` | only source sharing is exempt |
| `SHARED_DESTINATION_ONLY` | only destination sharing is exempt |
| `ANY_ENDPOINT` | any endpoint sharing is exempt |

The exemption is part of the policy, part of the proof dependency binding
(`DependencyBinding::endpoint_exemption`) and part of the semantic digest. Two proofs that
differ only in whether shared endpoints are exempt are different proofs with different
digests.

---

## 4. Complete versus incomplete evidence

This is the core invariant of the runtime.

If required failure-domain membership is incomplete, the runtime does **not** claim
independence merely because no shared domain was observed. **Absence of evidence is not
evidence of disjointness.** A policy that requires complete coverage returns
`UNKNOWN_INCOMPLETE_EVIDENCE` until coverage is complete, and an `UNKNOWN` can never be
downgraded into `PROVEN_DIVERSE`.

Coverage is a first-class fact, not a default:

| Coverage | Meaning |
| --- | --- |
| `COMPLETE` | the authority asserts the full membership set for this entity under this relation |
| `PARTIAL` | the authority holds some, but not demonstrably all, membership |
| `ABSENT` | the authority holds no classification for this entity under this relation |

`ABSENT` never means "belongs to no domain".

`CompletenessRequirement` decides how an observed conflict combines with outstanding
evidence:

* `REQUIRE_COMPLETE_EVIDENCE` (default) — any required class whose evidence is incomplete
  for any path yields `UNKNOWN_INCOMPLETE_EVIDENCE`, even when another required class
  already shows a concrete shared resource.
* `PROVEN_CONFLICT_DECISIVE` — a conflict that was actually observed is positive evidence
  and decides `NOT_DIVERSE` even while some other required class is still incomplete.
  Incomplete evidence without an observed conflict still yields
  `UNKNOWN_INCOMPLETE_EVIDENCE`.

Neither mode can produce `PROVEN_DIVERSE` from incomplete evidence.

---

## 5. Relationships to the surrounding authorities

**Path Authority.** Every current proof binds an exact `PathAuthorityGeneration` for every
path. A path whose bound generation is no longer the current authorized generation cannot
participate in a current proof: evaluation returns `STALE_PATH_AUTHORITY` or
`UNAUTHORIZED`. Path Diversity Fabric never overrides Path Authority. Historical proofs
remain historical; they never remain current.

**Fabric Topology.** Every proof binds the exact `TopologyGeneration` its path structure was
derived under, together with the exact set of structural entities it consulted. A topology
change invalidates precisely the proofs whose dependency footprint intersects the changed
entities; unrelated proofs stay current.

**Failure Domain Registry.** Every proof binds the exact `FailureDomainGeneration` and the
exact failure-domain and shared-risk-group identities it consulted. A membership or
classification change demotes precisely the dependent proofs.

**Fabric Epoch and publication authority.** Every authoritative publication binds
`CoordinatorEpoch`, `PublisherId`, `WorkerBootId`, scope, expected generation and
`MutationAttemptId`. Default deny: connected is not authorized.

---

## 6. Policy and proof identity

Both are strongly typed and never convert into one another: `DiversityPolicyId`,
`DiversityPolicyGeneration`, `DiversityProofId`, `DiversityProofGeneration`,
`PathSetId`, `PathId`, `PathAuthorityGeneration`, `TopologyGeneration`,
`FailureDomainGeneration`, `FailureDomainId`, `SharedRiskGroupId`, `PublisherId`,
`WorkerBootId`, `CoordinatorEpoch`, `MutationAttemptId`, `SnapshotId`. Zero is never a
legal required generation.

A `ProofRequest` binds an exact canonical path set plus exact generations. Path identity is
stable: the same request re-evaluated after an evidence change keeps its
`DiversityProofId` and advances `DiversityProofGeneration`. Path sets are canonicalized so
that input order never changes proof identity, the pairwise matrix order, conflict ordering,
witness selection, explanation ordering or digests. Duplicate paths in a proof set are
rejected: 1.0.0 gives duplicates no semantics.

The semantic digest covers the canonical path set, the policy identity and generation, every
bound dependency generation, the endpoint-exemption semantics, the proof result, every class
result with its evidence-completeness fact, the complete ordered conflict list, the witness
subset and the pairwise matrix. It excludes timestamps, thread ids, sockets, memory
addresses, arrival order, free-text detail strings, lifecycle, currentness, provenance and
diagnostic counters by construction: none of them is an input to it.

`LifecycleState` (what an operator did to a proof) and `Currentness` (whether the proof
still describes the world) are separate axes and are never merged. A `CURRENT` proof can be
stale; a `REVOKED` proof can be perfectly accurate. The transition table is explicit, and
`REVOKED` and `RETIRED` are terminal: a retired proof never reactivates.

---

## 7. Pairwise versus set-wise semantics

**`ALL_PAIRS`** — every pair of the canonical path set must satisfy every required class.

**`AT_LEAST_K_INDEPENDENT`** — a subset of at least `minimum_independent_paths` mutually
independent paths must exist. N-path diversity is never silently reduced to "P1 differs from
everyone".

For N paths the runtime exposes a deterministic canonical pairwise matrix (row-major upper
triangle over the canonical path order) and a conflict graph in which a vertex is a path and
an edge is a pair conflict under the required classes. K mutually independent paths are
exactly an independent set of size K in that graph.

The exact maximum independent set is computed by a memoized branch-and-bound search and
cross-checked by an independent exhaustive enumeration for path sets of up to 16 paths. The
two computations must agree; if they ever disagree the runtime refuses to make a negative
claim and returns `REVALIDATION_REQUIRED` instead.

The supported size is explicit, never a heuristic: K-subset analysis is bounded by
`Limits::max_k_subset_paths` (default 10). A larger set under `AT_LEAST_K` semantics is
refused with `RESOURCE_LIMIT` naming the exact bound. No greedy approximation is offered,
and no maximum-diversity claim is ever made from an unproven search.

---

## 8. Deterministic primary reason

When a proof is `NOT_DIVERSE` the runtime returns a deterministic primary conflict and a
bounded complete conflict list, ordered by a fixed total precedence:

```
SHARED_FAILURE_DOMAIN, SHARED_RISK_GROUP, SHARED_SITE, SHARED_POD, SHARED_RACK,
SHARED_POWER_DOMAIN, SHARED_CONDUIT, SHARED_COOLING, SHARED_DEVICE, SHARED_TRANSIT_NODE,
SHARED_LINK, SHARED_ENDPOINT
```

Correlated-failure relations come first because they cross otherwise disjoint topology.
Within one precedence level, resources are ordered by identity text. Independent input
ordering cannot change the primary reason. A bounded conflict list always reports how many
entries it dropped.

---

## 9. Invalidation, watermarks and revalidation

Evaluation is two-phase. Exact dependencies are snapshotted, evaluation runs outside the
state lock, the lock is reacquired, generations and watermarks are verified, and the result
is committed only if it is still current. No lock is ever held across a call into an evidence
view, a persistence write or a network operation.

A late result can never become current. If topology, failure-domain, policy, epoch or Path
Authority state moves while a proof is being evaluated, the revision is recorded as
explicitly not current and the caller receives `REVALIDATION_REQUIRED`.

After commit, currentness changes only through precise invalidation, never through a global
sweep:

* `demote_topology_entities` — demotes exactly the proofs whose recorded dependency
  footprint intersects the supplied entities
* `demote_failure_domain_generation`, `demote_domains`, `demote_path`, `demote_policy`,
  `demote_boot`
* `refresh_currentness` — re-checks Path Authority and policy currentness outside the lock
  and demotes exactly the proofs that no longer hold

Reverse indexes (`DiversityProofId` to proof, `PathId` to dependents, topology entity to
dependents, `FailureDomainId` and `SharedRiskGroupId` to dependents, policy to proofs,
`WorkerBootId` to publications, generation to dependents) make targeted invalidation
precise. A generation that cannot be attributed to specific entities can be invalidated
globally by watermark, and that choice is explicit at the call site. The dependency index is
bounded by `Limits::max_domain_evidence_entries`; generation-based invalidation stays exact
regardless of that bound.

`UNCHANGED` is a first-class mutation status: an exact revalidation that produces an
identical semantic digest advances nothing. An exact replay of an already-applied
`MutationAttemptId` with the same payload is `IDEMPOTENT`; the same attempt id with a
different payload is `ATTEMPT_CONFLICT`.

---

## 10. Persistence and recovery

The durable store persists policies, proof revisions and their retained history, canonical
path sets, the pairwise matrix, exact dependency generations, conflict lists, witness
subsets, lifecycle and currentness, provenance, digests and immutable snapshots. It uses a
versioned deterministic encoding, checked arithmetic, an integrity trailer and atomic
replacement through a temporary sibling file.

A mutation that requires durability is never acknowledged before the durable write succeeds.

Recovery is conservative: a store that cannot be fully validated is refused and the runtime
keeps exactly the state it had. The decoder rejects empty files, bad magic, unsupported
versions, truncations, bit flips, duplicate paths, malformed identities, undefined enum
encodings, impossible generations, pairwise-matrix dimension mismatches, conflicts that
reference unknown paths, a `PROVEN` claim with incomplete encoded evidence, invalid witness
subsets, absurd counts, arithmetic overflow and trailing bytes. A decoded digest is never
trusted: it is recomputed from the decoded content and a mismatch is a refusal.

---

## 11. Distributed publication authority and fencing

The distributed mode is a real loopback TCP client/server pair with an explicit wire version,
stable numeric message ids, bounded frame sizes, a deterministic encoding, integrity over the
semantic header and payload together, and strict trailing-byte and enum validation. No raw
C++ struct is ever serialized. Partial frames are bounded by product-level assembly
behaviour; exceeding the bound is an explicit failure rather than unbounded buffering.
Reserved message ids are refused rather than guessed at.

Every authoritative publication binds `CoordinatorEpoch`, `PublisherId`, `WorkerBootId`,
scope, expected generation and `MutationAttemptId`. Default deny: an unregistered boot is
unauthorized, a fenced boot is fenced permanently, and an epoch below the current epoch is
refused. A fresh process must present a fresh `WorkerBootId`, and a publisher that registers
a new boot permanently fences the boot it replaces.

When a worker connection is observed gone, the boot is fenced and every live publication
attributed to it is demoted immediately. A restarted coordinator restores durable state,
fences the old boots, restores **no** live publisher authority, and comes back at a strictly
higher epoch. There is one coordinator; this is not a consensus protocol and there is no
multi-coordinator replication.

As everywhere in this library, the integrity value detects corruption. It is **not** a
cryptographic authenticator and provides no defence against a motivated adversary.

---

## 12. Public API, package and consumer

```cmake
find_package(PathDiversityFabric CONFIG REQUIRED)
target_link_libraries(app PRIVATE SummonSoftwareLabs::PathDiversityFabric)
```

The installed package exports the headers and one target, and the library is usable as a
static or shared library. The independent consumer in `tests/consumer` constructs two paths,
proves link and node independence, injects a shared failure domain and observes
`NOT_DIVERSE`, removes required evidence for one path and observes
`UNKNOWN_INCOMPLETE_EVIDENCE`, then restores complete independent evidence and revalidates to
`PROVEN_DIVERSE`. No source-tree path leaks into the installed interface.

---

## 13. Limits

`Limits` bounds policy count, proof count, paths per proof, required classes, conflicts per
proof, pairwise cells, domain evidence entries, query results, retained history, batch size,
publishers, frame bytes, persistence record bytes, explanation entries, K-subset path count,
snapshot paths, identity length, tracked attempts, wire assembly bytes, store records, store
bytes, diff entries and topology dependencies. Every configured bound is consulted by the
subsystem named in its comment and is exercised by the test suite; there are no dead limits.
A refused operation names the exact bound, the observed magnitude and the allowed magnitude.

---

## 14. Examples, benchmarks and validation status

Eleven examples ship and all execute during closure: link-disjoint paths, node-disjoint with
endpoint exemption, shared-risk-group conflict, rack/pod/site diversity with authoritative
synthetic evidence, incomplete evidence `UNKNOWN`, N-path all-pairs proof, K-independent
subset, stale topology, worker reincarnation, coordinator restart and persistence recovery.

`path_diversity_benchmarks` reports measured, completed operations for synthetic
populations: pairwise and N-path proofs at path-set sizes 2/4/8/16, bounded K-subset proofs,
targeted invalidation, explanation, snapshot and digest, persistence save and load, and large
proof populations with many proofs sharing one path, mass topology invalidation and mass
domain reclassification.

**REAL** — real operating-system process death and restart of both workers and coordinators,
loopback TCP transport, durable persistence with atomic replacement, and the independent
installed-package consumer. These are exercised by the test suites in `tests/`.

**SYNTHETIC** — every topology, placement and failure-domain population in the tests,
examples and benchmarks is fabricated in memory. Synthetic independence is not a physical
redundancy proof and is never described as one.

**UNSUPPORTED** — this runtime makes no claim about actual failover success, physical power
independence, physical multi-rack separation, traffic continuity, or any vendor integration.
It does not validate that a failover works; it validates that a declared independence
property is supported by the evidence it can see.

---

## 15. Genuine limitations

* No physical switch fabric, rack, power domain or SRLG is reachable from the build host.
  Placement and failure-domain validation is SYNTHETIC.
* Diversity is proven against the evidence the evaluator can see. Disagreement between an
  evaluator's evidence and the authority's evidence surfaces as a refused or stale proof,
  never as silent reconciliation.
* Path computation, path legality, ECMP, weighting, adaptive routing, route convergence,
  route provenance, traffic engineering, bandwidth reservation and physical failover are out
  of scope and not implemented.
* The distributed protocol runs over loopback TCP with a single coordinator. There is no
  multi-coordinator replication and no consensus between coordinators.
* The frame and store integrity values detect corruption; they are not cryptographic and
  provide no authentication.
* The dependency index used for entity-precise invalidation is bounded. Beyond that bound,
  generation-level invalidation remains exact but is coarser.
* K-subset analysis is exact for path sets up to `Limits::max_k_subset_paths` (default 10)
  and refuses larger sets under `AT_LEAST_K` semantics rather than approximating.
* No telemetry is transmitted. Path Diversity Fabric emits no network traffic other than the
  explicit loopback protocol of the distributed mode.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
