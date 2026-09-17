// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Synthetic benchmark run over the public API.
//
// EVERY population below is SYNTHETIC: fabricated topology, fabricated placement and fabricated
// failure domains produced by populate_synthetic_fabric from one fixed seed. These numbers measure
// this host, this build and this synthetic input. They are not a performance guarantee, they are
// not a capacity claim and they say nothing about a physical fabric.
//
// Usage: path_diversity_benchmarks [--large] [--scale <1|10|100>] [--help]
//   --scale 100 or --large adds the 100000 proof population. Without it the run stays well inside
//   a couple of minutes and prints that the 100000 scale was skipped.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "path_diversity/path_diversity.hpp"

#if !defined(PATH_DIVERSITY_BENCHMARK_TEMP_ROOT)
#define PATH_DIVERSITY_BENCHMARK_TEMP_ROOT "path_diversity_benchmark_tmp"
#endif

namespace {

using namespace path_diversity;
using Clock = std::chrono::steady_clock;

constexpr std::uint64_t kSeed = 20260101ULL;

int g_failures = 0;

double elapsed_ms(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}
std::string fixed(double value, int digits) {
  std::ostringstream stream;
  stream << std::fixed << std::setprecision(digits) << value;
  return stream.str();
}
std::string count_text(std::uint64_t value) { return std::to_string(value); }
void require(bool condition, const std::string& description) {
  if (!condition) {
    ++g_failures;
    std::cout << "BENCHMARK FAILURE: " << description << "\n";
  }
}
void report(const std::string& label, std::uint64_t ops, double milliseconds, const std::string& note) {
  const double seconds = milliseconds / 1000.0;
  const double rate = seconds > 0.0 ? static_cast<double>(ops) / seconds : 0.0;
  std::cout << "  " << label << ": ops=" << ops << " total=" << fixed(milliseconds, 2) << " ms rate=" << fixed(rate, 1)
            << " ops/s" << (note.empty() ? "" : (" " + note)) << "\n";
  std::cout.flush();
}

// The replay tracker bounds how many distinct mutation attempts one coordinator records, and the
// population benchmarks deliberately commit far more proofs than the default. Both bounds are
// raised here rather than silently reducing the measured population.
Limits bench_limits() {
  Limits limits;
  limits.max_attempts_tracked = 1000000;
  limits.max_proofs = 200000;
  limits.max_query_results = 1000000;
  return limits;
}
SyntheticFabricOptions fabric_options(std::uint32_t leaves, std::uint32_t spines) {
  SyntheticFabricOptions options;
  options.spine_count = spines;
  options.leaf_count = leaves;
  options.racks = 4;
  options.pods = 2;
  options.sites = 1;
  options.paths_per_pair = 1;
  options.complete_domain_coverage = true;
  options.seed = kSeed;
  return options;
}

// Deterministic lexicographic enumeration of fixed-size index combinations. Two runs of this
// program build exactly the same proof requests in exactly the same order.
class CombinationCursor {
 public:
  CombinationCursor(std::size_t pool, std::size_t size) : pool_(pool), combo_(size) {
    if (size == 0 || size > pool) {
      done_ = true;
      return;
    }
    for (std::size_t index = 0; index < size; ++index) {
      combo_[index] = static_cast<std::uint32_t>(index);
    }
  }
  bool done() const { return done_; }
  const std::vector<std::uint32_t>& current() const { return combo_; }
  void advance() {
    for (std::size_t index = combo_.size(); index-- > 0;) {
      const std::uint32_t limit = static_cast<std::uint32_t>(pool_ - (combo_.size() - index));
      if (combo_[index] < limit) {
        ++combo_[index];
        for (std::size_t next = index + 1; next < combo_.size(); ++next) {
          combo_[next] = combo_[next - 1] + 1;
        }
        return;
      }
    }
    done_ = true;
  }

 private:
  std::size_t pool_ = 0;
  std::vector<std::uint32_t> combo_;
  bool done_ = false;
};

// One synthetic evidence set, one publication authority and one runtime, with a registered
// publisher acting under the current coordinator epoch.
struct Scenario {
  explicit Scenario(const Limits& configured)
      : evidence(), publication(configured), runtime(evidence, evidence, evidence, publication, configured) {}
  ActingAuthority actor() {
    ActingAuthority authority;
    authority.epoch = publication.current_epoch();
    authority.publisher = publisher;
    authority.boot = boot;
    authority.scope = default_scope();
    authority.attempt = MutationAttemptId::parse("attempt-bench-" + std::to_string(++serial));
    return authority;
  }
  bool register_publisher() {
    publisher = mint_publisher_id("bench");
    boot = mint_worker_boot_id();
    PublisherSession session;
    session.publisher = publisher;
    session.boot = boot;
    session.epoch = publication.current_epoch();
    session.scope = default_scope();
    return publication.register_publisher(session) == AuthorityStatus::ACCEPTED;
  }
  void feed(const SyntheticFabricOptions& options) {
    fabric = populate_synthetic_fabric(evidence, options);
    refs.clear();
    for (const SyntheticPath& entry : fabric.paths) {
      refs.push_back(PathRef{entry.path, entry.authority_generation});
    }
  }
  InMemoryEvidence evidence;
  PublicationAuthority publication;
  DiversityRuntime runtime;
  SyntheticFabric fabric;
  std::vector<PathRef> refs;
  PublisherId publisher;
  WorkerBootId boot;
  std::uint64_t serial = 0;
};

struct CommitTally {
  std::uint64_t applied = 0, unchanged = 0, other = 0, witness_at_least_k = 0;
};

// Commits one proof per enumerated combination. A prefix is prepended to every request so a whole
// population of proofs can be made to share one exact path.
CommitTally commit_combinations(Scenario& scenario, const DiversityPolicyId& policy, DiversityPolicyGeneration generation,
                                const std::vector<PathRef>& prefix, const std::vector<PathRef>& pool, std::size_t set_size,
                                std::size_t iterations, std::uint32_t requested_k) {
  CommitTally tally;
  CombinationCursor cursor(pool.size(), set_size);
  while (iterations > 0 && !cursor.done()) {
    ProofRequest request;
    request.policy = policy;
    request.policy_generation = generation;
    request.paths = prefix;
    for (std::uint32_t index : cursor.current()) {
      request.paths.push_back(pool[index]);
    }
    const MutationResult result = scenario.runtime.evaluate(request, scenario.actor());
    if (result.status == MutationStatus::APPLIED) { ++tally.applied; }
    else if (result.status == MutationStatus::UNCHANGED) { ++tally.unchanged; }
    else { ++tally.other; }
    if (result.has_proof && result.proof.witness.present && result.proof.witness.achieved >= requested_k) {
      ++tally.witness_at_least_k;
    }
    --iterations;
    cursor.advance();
  }
  return tally;
}
bool publish(Scenario& scenario, const DiversityPolicy& policy) {
  const MutationResult result = scenario.runtime.publish_policy(policy, scenario.actor());
  require(result.has_policy, "policy publication for " + policy.id.str());
  return result.has_policy;
}
std::vector<PathRef> first_paths(const Scenario& scenario, std::size_t count) {
  const std::size_t available = scenario.refs.size() < count ? scenario.refs.size() : count;
  return std::vector<PathRef>(scenario.refs.begin(), scenario.refs.begin() + static_cast<std::ptrdiff_t>(available));
}
std::vector<EntityRef> fabric_entities(const Scenario& scenario) {
  std::vector<EntityRef> entities;
  for (const PathRef& reference : scenario.refs) {
    const std::optional<PathComposition> composition = scenario.evidence.composition(reference.path);
    if (!composition.has_value()) {
      continue;
    }
    for (const LinkId& link : composition->links) { entities.push_back(EntityRef{EntityKind::LINK, link.str()}); }
    for (const DeviceId& device : composition->devices) { entities.push_back(EntityRef{EntityKind::DEVICE, device.str()}); }
    for (const NodeId& node : composition->transit_nodes) { entities.push_back(EntityRef{EntityKind::NODE, node.str()}); }
    for (const NodeId& node : composition->sources) { entities.push_back(EntityRef{EntityKind::ENDPOINT, node.str()}); }
    for (const NodeId& node : composition->destinations) { entities.push_back(EntityRef{EntityKind::ENDPOINT, node.str()}); }
  }
  std::sort(entities.begin(), entities.end());
  entities.erase(std::unique(entities.begin(), entities.end()), entities.end());
  return entities;
}

// --- Sections ----------------------------------------------------------------------------------
void bench_path_set_sizes() {
  std::cout << "\nproof evaluation: pairwise (2) and N-path all-pairs sets, population=SYNTHETIC\n";
  Scenario scenario(bench_limits());
  require(scenario.register_publisher(), "publisher registration");
  scenario.feed(fabric_options(64, 4));
  const DiversityPolicy policy = synthetic_policy("dpol-bench-allpairs", default_scope(), SetSemantics::ALL_PAIRS, 2);
  if (!publish(scenario, policy)) { return; }
  const DiversityPolicyGeneration generation = scenario.runtime.policy_generation(policy.id);
  struct Case { std::size_t set_size, iterations, pool; };
  const Case cases[] = {{2, 1000, 64}, {4, 600, 32}, {8, 300, 24}, {16, 120, 24}};
  for (const Case& item : cases) {
    const std::vector<PathRef> pool = first_paths(scenario, item.pool);
    const Clock::time_point start = Clock::now();
    const CommitTally tally = commit_combinations(scenario, policy.id, generation, {}, pool, item.set_size, item.iterations, 0);
    report("path-set-" + count_text(item.set_size) + " all-pairs proof", tally.applied + tally.unchanged, elapsed_ms(start),
           "committed=" + count_text(tally.applied) + " unchanged=" + count_text(tally.unchanged) + " other=" +
               count_text(tally.other) + " requested=" + count_text(item.iterations));
  }
  std::cout << "  registry after this section: proofs=" << scenario.runtime.proof_count() << "\n";
}

void bench_k_subset() {
  std::cout << "\nbounded K-subset proof: AT_LEAST_K_INDEPENDENT, K=3, 8-path sets, population=SYNTHETIC\n";
  Scenario scenario(bench_limits());
  require(scenario.register_publisher(), "publisher registration");
  scenario.feed(fabric_options(24, 4));
  DiversityPolicy link_only = synthetic_policy("dpol-bench-ksubset-link", default_scope(), SetSemantics::AT_LEAST_K_INDEPENDENT, 3);
  link_only.required_classes = {DiversityClass::LINK_DISJOINT};
  link_only.endpoint_exemption = EndpointExemption::NONE;
  link_only.allowed_failure_domain_relations.clear();
  link_only.description = "synthetic link-only bounded-K profile";
  link_only.canonicalize();
  const DiversityPolicy policies[] = {
      synthetic_policy("dpol-bench-ksubset", default_scope(), SetSemantics::AT_LEAST_K_INDEPENDENT, 3), link_only};
  const std::vector<PathRef> pool = first_paths(scenario, 24);
  for (const DiversityPolicy& policy : policies) {
    if (!publish(scenario, policy)) { return; }
    const DiversityPolicyGeneration generation = scenario.runtime.policy_generation(policy.id);
    const Clock::time_point start = Clock::now();
    const CommitTally tally = commit_combinations(scenario, policy.id, generation, {}, pool, 8, 100, 3);
    report("at-least-3-independent 8-path proof, classes=" + count_text(policy.required_classes.size()), tally.applied,
           elapsed_ms(start),
           "witness-achieved>=3 on " + count_text(tally.witness_at_least_k) + " of " + count_text(tally.applied) +
               "; solver bound max_k_subset_paths=" + count_text(scenario.runtime.limits().max_k_subset_paths));
    std::map<std::uint32_t, std::uint64_t> distribution;
    for (const DiversityProofId& id : scenario.runtime.proofs_for_policy(policy.id).proofs) {
      const std::optional<DiversityProof> proof = scenario.runtime.proof(id);
      if (proof.has_value()) { ++distribution[proof->witness.achieved]; }
    }
    std::cout << "  witness achieved distribution for " << policy.id.str() << " (achieved=proofs):";
    for (const auto& entry : distribution) { std::cout << " " << entry.first << "=" << entry.second; }
    std::cout << "\n";
  }
}

void bench_targeted_invalidation() {
  std::cout << "\ntargeted invalidation fan-out: demote_topology_entities, population=SYNTHETIC\n";
  Scenario scenario(bench_limits());
  require(scenario.register_publisher(), "publisher registration");
  scenario.feed(fabric_options(32, 4));
  const DiversityPolicy policy = synthetic_policy("dpol-bench-invalidate", default_scope(), SetSemantics::ALL_PAIRS, 2);
  if (!publish(scenario, policy)) { return; }
  const DiversityPolicyGeneration generation = scenario.runtime.policy_generation(policy.id);
  const std::vector<PathRef> pool = first_paths(scenario, 32);
  const Clock::time_point populate_start = Clock::now();
  const CommitTally tally = commit_combinations(scenario, policy.id, generation, {}, pool, 2, 496, 0);
  report("invalidation population (all 2-path sets)", tally.applied, elapsed_ms(populate_start),
         "fabric-paths=32 proofs=" + count_text(scenario.runtime.proof_count()));
  const std::uint64_t before = scenario.runtime.current_proofs().total;
  std::uint64_t demoted = 0;
  std::uint64_t hot_fan_out = 0;
  const Clock::time_point start = Clock::now();
  for (std::uint32_t index = 0; index < 8; ++index) {
    const EntityRef entity{EntityKind::LINK, "link-host-" + count_text(index) + "-leaf-" + count_text(index)};
    const std::vector<DiversityProofId> affected = scenario.runtime.demote_topology_entities({entity}, TopologyGeneration::from_value(2));
    hot_fan_out = affected.size() > hot_fan_out ? affected.size() : hot_fan_out;
    demoted += affected.size();
  }
  report("targeted topology invalidation (8 links)", demoted, elapsed_ms(start),
         "largest single-entity fan-out=" + count_text(hot_fan_out) + " current-before=" + count_text(before));
  const Clock::time_point cold_start = Clock::now();
  const std::vector<DiversityProofId> cold =
      scenario.runtime.demote_topology_entities({EntityRef{EntityKind::NODE, "spine-99"}}, TopologyGeneration::from_value(2));
  report("targeted invalidation of an unrelated entity (must demote 0)", cold.size(), elapsed_ms(cold_start),
         "current-after=" + count_text(scenario.runtime.current_proofs().total));
  require(cold.empty(), "an entity no proof depends on must demote nothing");
  require(scenario.runtime.current_proofs().total == before - demoted, "targeted invalidation must be exact");
}

void bench_explanation_and_snapshot() {
  std::cout << "\nexplanation and snapshot/digest cost, population=SYNTHETIC\n";
  Scenario scenario(bench_limits());
  require(scenario.register_publisher(), "publisher registration");
  scenario.feed(fabric_options(16, 4));
  const DiversityPolicy policy = synthetic_policy("dpol-bench-explain", default_scope(), SetSemantics::ALL_PAIRS, 2);
  if (!publish(scenario, policy)) { return; }
  const DiversityPolicyGeneration generation = scenario.runtime.policy_generation(policy.id);
  const CommitTally tally = commit_combinations(scenario, policy.id, generation, {}, first_paths(scenario, 16), 4, 200, 0);
  require(tally.applied == 200, "200 distinct 4-path proofs committed");
  const std::vector<DiversityProofId> ids = scenario.runtime.all_proofs().proofs;
  std::uint64_t entries = 0;
  Clock::time_point start = Clock::now();
  for (const DiversityProofId& id : ids) {
    const std::optional<Explanation> explanation = scenario.runtime.explain(id);
    require(explanation.has_value(), "explanation for a stored proof");
    entries += explanation.has_value() ? explanation->entries.size() : 0;
  }
  report("explain_proof", ids.size(), elapsed_ms(start), "explanation entries=" + count_text(entries));
  std::uint64_t snapshot_checksum = 0;
  start = Clock::now();
  for (const DiversityProofId& id : ids) {
    const std::optional<ProofSnapshot> snapshot = scenario.runtime.snapshot(id);
    require(snapshot.has_value(), "snapshot for a stored proof");
    snapshot_checksum += snapshot.has_value() ? snapshot->digest.low64() : 0;
  }
  report("snapshot retrieval", ids.size(), elapsed_ms(start), "checksum=" + count_text(snapshot_checksum));

  const std::optional<DiversityProof> proof = scenario.runtime.proof(ids.front());
  require(proof.has_value(), "stored proof for digest measurement");
  if (!proof.has_value()) { return; }
  const std::size_t digest_iterations = 2000;
  std::uint64_t checksum = 0;
  start = Clock::now();
  for (std::size_t index = 0; index < digest_iterations; ++index) {
    checksum += proof_semantic_digest(*proof).low64();
  }
  report("proof_semantic_digest", digest_iterations, elapsed_ms(start), "checksum=" + count_text(checksum));
  const std::size_t capture_iterations = 1000;
  checksum = 0;
  start = Clock::now();
  for (std::size_t index = 0; index < capture_iterations; ++index) {
    const ProofSnapshot snapshot = capture_snapshot(*proof);
    checksum += snapshot.digest.low64();
  }
  report("capture_snapshot", capture_iterations, elapsed_ms(start), "checksum=" + count_text(checksum));
}

void bench_persistence() {
  std::cout << "\npersistence save and load, population=SYNTHETIC\n";
  Scenario scenario(bench_limits());
  require(scenario.register_publisher(), "publisher registration");
  scenario.feed(fabric_options(48, 4));
  const DiversityPolicy policy = synthetic_policy("dpol-bench-store", default_scope(), SetSemantics::ALL_PAIRS, 2);
  if (!publish(scenario, policy)) { return; }
  const DiversityPolicyGeneration generation = scenario.runtime.policy_generation(policy.id);
  const CommitTally tally = commit_combinations(scenario, policy.id, generation, {}, first_paths(scenario, 48), 2, 1000, 0);
  require(tally.applied == 1000, "1000 distinct 2-path proofs committed before saving");
  const std::filesystem::path root(PATH_DIVERSITY_BENCHMARK_TEMP_ROOT);
  std::error_code error;
  std::filesystem::create_directories(root, error);
  const std::filesystem::path store = root / "path_diversity_bench_store.pdk";
  Clock::time_point start = Clock::now();
  const PersistenceStatus saved = scenario.runtime.save(store.string());
  report("persistence save", tally.applied, elapsed_ms(start), "status=" + std::string(to_string(saved)));
  require(saved == PersistenceStatus::OK, "store written to " + store.string());
  const std::uint64_t bytes = saved == PersistenceStatus::OK ? static_cast<std::uint64_t>(std::filesystem::file_size(store, error)) : 0;
  std::cout << "  store path=" << store.string() << " bytes=" << bytes << "\n";
  Scenario reloaded(bench_limits());
  require(reloaded.register_publisher(), "publisher registration on the recovering runtime");
  start = Clock::now();
  const PersistenceStatus loaded = reloaded.runtime.load(store.string());
  report("persistence load", tally.applied, elapsed_ms(start), "status=" + std::string(to_string(loaded)));
  require(loaded == PersistenceStatus::OK, "store read back from " + store.string());
  require(reloaded.runtime.proof_count() == scenario.runtime.proof_count(), "load restores every proof");
  require(reloaded.runtime.policy_count() == scenario.runtime.policy_count(), "load restores every policy");
  std::cout << "  round trip: proofs " << scenario.runtime.proof_count() << " -> " << reloaded.runtime.proof_count()
            << ", policies " << scenario.runtime.policy_count() << " -> " << reloaded.runtime.policy_count() << "\n";
  std::filesystem::remove(store, error);
}

std::size_t minimal_paths_for_pairs(std::uint64_t pairs) {
  std::size_t paths = 2;
  while ((paths * (paths - 1)) / 2 < pairs) { ++paths; }
  return paths;
}

void bench_population(std::uint64_t scale) {
  const std::size_t paths = minimal_paths_for_pairs(scale);
  Scenario scenario(bench_limits());
  require(scenario.register_publisher(), "publisher registration");
  scenario.feed(fabric_options(static_cast<std::uint32_t>(paths), 4));
  const DiversityPolicy policy = synthetic_policy("dpol-bench-population", default_scope(), SetSemantics::ALL_PAIRS, 2);
  if (!publish(scenario, policy)) { return; }
  const DiversityPolicyGeneration generation = scenario.runtime.policy_generation(policy.id);
  const Clock::time_point start = Clock::now();
  const CommitTally tally = commit_combinations(scenario, policy.id, generation, {}, scenario.refs, 2, static_cast<std::size_t>(scale), 0);
  report("proof population " + count_text(scale), tally.applied, elapsed_ms(start),
         "synthetic-fabric-paths=" + count_text(paths) + " unchanged=" + count_text(tally.unchanged) + " other=" +
             count_text(tally.other) + " registry=" + count_text(scenario.runtime.proof_count()));
  require(tally.applied == scale, "the whole population of " + count_text(scale) + " proofs committed");
  const Clock::time_point query_start = Clock::now();
  const DiversityRuntime::QueryResult query = scenario.runtime.proofs_for_path(scenario.refs.front().path);
  report("population query proofs_for_path", query.total, elapsed_ms(query_start),
         "truncated=" + std::string(query.truncated ? "true" : "false"));
}

void bench_shared_path_and_mass_invalidation() {
  std::cout << "\nmany proofs sharing one path, mass topology invalidation, mass domain reclassification, population=SYNTHETIC\n";
  const Limits limits = bench_limits();
  const std::vector<FailureDomainId> domains = {
      FailureDomainId::parse("fd-0"), FailureDomainId::parse("fd-1"), FailureDomainId::parse("fd-2"), FailureDomainId::parse("fd-3"),
      FailureDomainId::parse("rack-0"), FailureDomainId::parse("rack-1"), FailureDomainId::parse("rack-2"), FailureDomainId::parse("rack-3"),
      FailureDomainId::parse("pod-0"), FailureDomainId::parse("pod-1"), FailureDomainId::parse("site-0")};
  {
    Scenario scenario(limits);
    require(scenario.register_publisher(), "publisher registration");
    scenario.feed(fabric_options(65, 4));
    const DiversityPolicy policy = synthetic_policy("dpol-bench-shared", default_scope(), SetSemantics::ALL_PAIRS, 2);
    if (!publish(scenario, policy)) { return; }
    const std::vector<PathRef> shared = first_paths(scenario, 1);
    const std::vector<PathRef> others(scenario.refs.begin() + 1, scenario.refs.end());
    const Clock::time_point commit_start = Clock::now();
    const CommitTally tally = commit_combinations(scenario, policy.id, scenario.runtime.policy_generation(policy.id), shared, others, 2, 2000, 0);
    report("population of proofs sharing one exact path", tally.applied, elapsed_ms(commit_start),
           "shared-path=" + shared.front().path.str() + " registry=" + count_text(scenario.runtime.proof_count()));
    require(tally.applied == 2000, "2000 proofs share one exact path");
    const Clock::time_point query_start = Clock::now();
    const DiversityRuntime::QueryResult query = scenario.runtime.proofs_for_path(shared.front().path);
    report("query proofs_for_path on the shared path", query.total, elapsed_ms(query_start),
           "truncated=" + std::string(query.truncated ? "true" : "false"));
    const Clock::time_point demote_start = Clock::now();
    const std::vector<DiversityProofId> affected = scenario.runtime.demote_path(shared.front().path);
    report("demote_path fan-out for the shared path", affected.size(), elapsed_ms(demote_start),
           "current-after=" + count_text(scenario.runtime.current_proofs().total));
    require(affected.size() == tally.applied, "demote_path demotes exactly the proofs that bind the path");
  }
  {
    Scenario scenario(limits);
    require(scenario.register_publisher(), "publisher registration");
    scenario.feed(fabric_options(64, 4));
    const DiversityPolicy policy = synthetic_policy("dpol-bench-topology", default_scope(), SetSemantics::ALL_PAIRS, 2);
    if (!publish(scenario, policy)) { return; }
    const CommitTally tally = commit_combinations(scenario, policy.id, scenario.runtime.policy_generation(policy.id), {},
                                                  first_paths(scenario, 64), 2, 2000, 0);
    require(tally.applied == 2000, "2000 proofs committed before mass topology invalidation");
    const std::vector<EntityRef> entities = fabric_entities(scenario);
    const Clock::time_point entity_start = Clock::now();
    const std::vector<DiversityProofId> by_entity = scenario.runtime.demote_topology_entities(entities, TopologyGeneration::from_value(2));
    report("mass topology invalidation by entity", by_entity.size(), elapsed_ms(entity_start),
           "entities=" + count_text(entities.size()) + " registry=" + count_text(scenario.runtime.proof_count()));
    require(by_entity.size() == tally.applied, "every proof depends on some entity of the changed topology");
    const Clock::time_point generation_start = Clock::now();
    const std::vector<DiversityProofId> by_generation = scenario.runtime.demote_topology_generation(TopologyGeneration::from_value(3));
    report("mass topology invalidation by generation", by_generation.size(), elapsed_ms(generation_start),
           "already-demoted proofs are not demoted twice");
    require(by_generation.empty(), "a second invalidation of demoted proofs must be a no-op");
  }
  {
    Scenario scenario(limits);
    require(scenario.register_publisher(), "publisher registration");
    scenario.feed(fabric_options(64, 4));
    const DiversityPolicy policy = synthetic_policy("dpol-bench-domains", default_scope(), SetSemantics::ALL_PAIRS, 2);
    if (!publish(scenario, policy)) { return; }
    const CommitTally tally = commit_combinations(scenario, policy.id, scenario.runtime.policy_generation(policy.id), {},
                                                  first_paths(scenario, 64), 2, 2000, 0);
    require(tally.applied == 2000, "2000 proofs committed before mass domain reclassification");
    const Clock::time_point domains_start = Clock::now();
    const std::vector<DiversityProofId> by_domain = scenario.runtime.demote_domains(domains, FailureDomainGeneration::from_value(2));
    report("mass domain reclassification by domain identity", by_domain.size(), elapsed_ms(domains_start),
           "domains=" + count_text(domains.size()));
    const Clock::time_point generation_start = Clock::now();
    const std::vector<DiversityProofId> by_generation = scenario.runtime.demote_failure_domain_generation(FailureDomainGeneration::from_value(3));
    report("mass failure-domain invalidation by generation", by_generation.size(), elapsed_ms(generation_start),
           "already-demoted proofs are not demoted twice");
  }
}

void print_header() {
  const Limits limits = bench_limits();
  std::cout << "Path Diversity Fabric " << version_string() << " synthetic benchmark run\n";
  std::cout << "ALL POPULATIONS ARE SYNTHETIC: fabricated topology, fabricated placement, fabricated failure domains, built once from one seed.\n";
  std::cout << "seed=" << kSeed << " (the generator is a pure function of the seed and the options)\n";
  std::cout << "temporary root=" << PATH_DIVERSITY_BENCHMARK_TEMP_ROOT << " configured limits: max_proofs=" << limits.max_proofs
            << " max_attempts_tracked=" << limits.max_attempts_tracked << " max_query_results=" << limits.max_query_results << "\n";
  std::cout << "Each figure is one wall-clock measurement on a shared host; rates vary with load.\n";
  std::cout << "No performance guarantee is made. No measurement here is a claim about a physical fabric.\n";
}
void print_usage(std::ostream& out) {
  out << "usage: path_diversity_benchmarks [--large] [--scale <1|10|100>] [--help]\n"
         "  --large        also run the 100000 proof population\n"
         "  --scale <n>    largest proof population in thousands: 1, 10 or 100\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::uint32_t max_thousands = 10;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--help") { print_usage(std::cout); return 0; }
    if (argument == "--large") { max_thousands = 100; continue; }
    if (argument == "--scale") {
      if (index + 1 >= argc) {
        std::cerr << "path_diversity_benchmarks: --scale requires a value\n";
        print_usage(std::cerr);
        return 2;
      }
      const std::string value = argv[++index];
      if (value != "1" && value != "10" && value != "100") {
        std::cerr << "path_diversity_benchmarks: --scale accepts 1, 10 or 100\n";
        print_usage(std::cerr);
        return 2;
      }
      max_thousands = value == "1" ? 1U : (value == "10" ? 10U : 100U);
      continue;
    }
    std::cerr << "path_diversity_benchmarks: unknown option " << argument << "\n";
    print_usage(std::cerr);
    return 2;
  }

  print_header();
  bench_path_set_sizes();
  bench_k_subset();
  bench_targeted_invalidation();
  bench_explanation_and_snapshot();
  bench_persistence();
  std::cout << "\nproof population scales (SYNTHETIC)\n";
  bench_population(1000);
  if (max_thousands >= 10) { bench_population(10000); }
  else { std::cout << "  proof population 10000: SKIPPED (--scale 10 or more)\n"; }
  if (max_thousands >= 100) { bench_population(100000); }
  else {
    std::cout << "  proof population 100000: SKIPPED (pass --large or --scale 100; the default run stays inside a couple of minutes)\n";
  }
  bench_shared_path_and_mass_invalidation();
  std::cout << "\nbenchmark complete: failures=" << g_failures << "\n";
  return g_failures == 0 ? 0 : 1;
}
