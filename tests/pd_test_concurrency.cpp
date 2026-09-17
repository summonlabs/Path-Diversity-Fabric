// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Contention coverage. Every rendezvous is a std::barrier and every wait is a
// race-free atomic spin, so correctness never depends on elapsed time. Worker
// threads never touch the harness: they record violations locally and the main
// thread asserts on the collected reports.

#include <atomic>
#include <barrier>
#include <cstdint>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

constexpr std::uint32_t kEvaluatorThreads = 4;
constexpr std::uint32_t kPathPairs = 8;
constexpr std::uint32_t kRounds = 6;
constexpr std::uint32_t kPairsPerThread = kPathPairs / kEvaluatorThreads;
constexpr std::uint32_t kCallsPerThread = kRounds * kPairsPerThread;
constexpr std::uint32_t kTotalCalls = kEvaluatorThreads * kCallsPerThread;

// Per-thread findings. A worker thread never calls into the harness, so the
// shared assertion counter is only ever touched by the main thread.
struct Report {
  std::uint64_t snapshots = 0;
  std::uint64_t proofs_seen = 0;
  std::uint64_t violations = 0;
  std::string first_violation;
  bool counter_went_backwards = false;
  bool bound_a_future_generation = false;
  bool observed_while_writers_ran = false;
  RuntimeStats last_stats{};
};

void note(Report& report, bool ok, const std::string& detail) {
  if (ok) {
    return;
  }
  ++report.violations;
  if (report.first_violation.empty()) {
    report.first_violation = detail;
  }
}

// A committed revision must be structurally complete whatever instant a reader
// catches it: a half-built record would show up here.
bool revision_is_well_formed(const DiversityProof& proof, std::string& why) {
  const std::size_t path_count = proof.request.paths.size();
  if (path_count < 2) {
    why = "fewer than two paths";
    return false;
  }
  if (!proof.generation.is_set()) {
    why = "generation is unset";
    return false;
  }
  // A revision carries either a complete matrix or none at all: an evaluation
  // rejected before evidence collection (a stale generation, a revoked path) or
  // rewritten as a watermark drift has no evidence to describe. A decisive
  // verdict without a matrix, or a matrix with a missing half, is a violation.
  const bool has_order = !proof.matrix.order.empty();
  const bool has_cells = !proof.matrix.cells.empty();
  if (!has_order && !has_cells) {
    if (proof.outcome == ProofOutcome::PROVEN_DIVERSE ||
        proof.outcome == ProofOutcome::NOT_DIVERSE ||
        proof.outcome == ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE) {
      why = "a decisive outcome carried no matrix";
      return false;
    }
    return true;
  }
  if (!has_order || !has_cells) {
    why = "a partially built matrix was observed";
    return false;
  }
  if (proof.matrix.order.size() != path_count) {
    why = "matrix order does not match the request (order=" +
          std::to_string(proof.matrix.order.size()) + " request=" + std::to_string(path_count) +
          " generation=" + std::to_string(proof.generation.value()) + " outcome=" +
          std::string(to_string(proof.outcome)) + ")";
    return false;
  }
  if (proof.matrix.cells.size() != PairwiseMatrix::cell_count(path_count)) {
    why = "matrix cell count does not match the order";
    return false;
  }
  if (proof.dependencies.paths.size() != path_count) {
    why = "dependency path list does not match the request";
    return false;
  }
  for (std::size_t index = 0; index < path_count; ++index) {
    if (!(proof.matrix.order[index] == proof.request.paths[index].path) ||
        !(proof.dependencies.paths[index].path == proof.request.paths[index].path)) {
      why = "matrix or dependency order disagrees with the request";
      return false;
    }
  }
  for (const PairwiseCell& cell : proof.matrix.cells) {
    if (!(cell.left < cell.right) || cell.right >= path_count) {
      why = "cell indices are not a canonical pair";
      return false;
    }
  }
  if (proof.conflicts.size() > proof.matrix.cells.size() + proof.classes.size() + 1) {
    why = "conflict list is not bounded by the evaluation it came from";
    return false;
  }
  return true;
}

// Validates one registry snapshot: every advertised identity resolves, every
// returned revision is complete, the totals agree and the counters are monotone.
void audit_registry(const DiversityRuntime& runtime, const Limits& limits, Report& report) {
  const DiversityRuntime::QueryResult all = runtime.all_proofs();
  const std::size_t count = runtime.proof_count();
  ++report.snapshots;
  // The registry only grows in this suite, so a count read after the snapshot is
  // an upper bound for it and the comparison stays sound under contention.
  note(report, all.total <= count, "a snapshot advertised more proofs than the registry holds");
  note(report, all.proofs.size() <= static_cast<std::size_t>(limits.max_query_results),
       "a snapshot returned more proofs than max_query_results allows");
  note(report, !runtime.render().empty(), "the diagnostic dump was empty");
  const DiversityRuntime::QueryResult current = runtime.current_proofs();
  note(report, current.total <= runtime.proof_count(),
       "the current set exceeded the whole registry");
  for (const DiversityProofId& id : all.proofs) {
    const std::optional<DiversityProof> proof = runtime.proof(id);
    note(report, proof.has_value(), "an advertised proof identity did not resolve");
    if (!proof.has_value()) {
      continue;
    }
    ++report.proofs_seen;
    note(report, proof->id == id, "a stored revision carries a different identity");
    std::string why;
    const bool well_formed = revision_is_well_formed(*proof, why);
    note(report, well_formed, "an incomplete revision was observed: outcome=" +
                                  std::string(to_string(proof->outcome)) + " lifecycle=" +
                                  std::string(to_string(proof->lifecycle)) + " " + why);
    const DiversityRuntime::QueryResult by_policy =
        runtime.proofs_for_policy(proof->request.policy);
    bool found = false;
    for (const DiversityProofId& candidate : by_policy.proofs) {
      found = found || (candidate == id);
    }
    note(report, found, "the reverse policy index did not resolve a committed proof");
  }
  const RuntimeStats now = runtime.stats();
  if (now.evaluations < report.last_stats.evaluations || now.commits < report.last_stats.commits ||
      now.demotions < report.last_stats.demotions ||
      now.invalidations < report.last_stats.invalidations) {
    report.counter_went_backwards = true;
  }
  report.last_stats = now;
}

std::string pair_tag(std::uint32_t index, const char* suffix) {
  return "conc-" + std::string(suffix) + "-" + std::to_string(index);
}

struct Pair {
  std::string first;
  std::string second;
  std::string first_suffix;
  std::string second_suffix;
};

Pair pair_at(std::uint32_t index) {
  const std::string suffix = std::to_string(index);
  return Pair{pair_tag(index, "a"), pair_tag(index, "b"), suffix, suffix};
}

void install_pair(pd_test::Fixture& fixture, std::uint32_t index) {
  const Pair pair = pair_at(index);
  fixture.evidence.set_path(pd_test::make_path(pair.first, 1, {"node-a-" + pair.first_suffix},
                                               {"link-a-" + pair.first_suffix},
                                               {"dev-a-" + pair.first_suffix},
                                               "ep-src-" + pair.first_suffix,
                                               "ep-dst-" + pair.first_suffix));
  fixture.evidence.set_path(pd_test::make_path(pair.second, 1, {"node-b-" + pair.second_suffix},
                                               {"link-b-" + pair.second_suffix},
                                               {"dev-b-" + pair.second_suffix},
                                               "ep-src-" + pair.second_suffix,
                                               "ep-dst-" + pair.second_suffix));
}

std::vector<Pair> install_pairs(pd_test::Fixture& fixture, std::uint32_t count) {
  std::vector<Pair> pairs;
  for (std::uint32_t index = 0; index < count; ++index) {
    install_pair(fixture, index);
    pairs.push_back(pair_at(index));
  }
  return pairs;
}

// Relabels every installed path with a new topology generation, so the topology
// writer moves the served generation and the compositions together.
void relabel_topology(pd_test::Fixture& fixture, std::uint32_t count,
                      TopologyGeneration generation) {
  for (std::uint32_t index = 0; index < count; ++index) {
    const Pair pair = pair_at(index);
    PathComposition first = pd_test::make_path(pair.first, 1, {"node-a-" + pair.first_suffix},
                                               {"link-a-" + pair.first_suffix},
                                               {"dev-a-" + pair.first_suffix},
                                               "ep-src-" + pair.first_suffix,
                                               "ep-dst-" + pair.first_suffix);
    PathComposition second = pd_test::make_path(pair.second, 1, {"node-b-" + pair.second_suffix},
                                                {"link-b-" + pair.second_suffix},
                                                {"dev-b-" + pair.second_suffix},
                                                "ep-src-" + pair.second_suffix,
                                                "ep-dst-" + pair.second_suffix);
    first.topology_generation = generation;
    second.topology_generation = generation;
    fixture.evidence.set_path(std::move(first));
    fixture.evidence.set_path(std::move(second));
  }
  fixture.evidence.set_topology_generation(generation);
}

struct PublishedPolicy {
  DiversityPolicyId id;
  DiversityPolicyGeneration generation;
};

PublishedPolicy publish_links_policy(pd_test::Fixture& fixture) {
  const DiversityPolicy policy = pd_test::make_policy(
      "dpol-concurrency", {DiversityClass::LINK_DISJOINT}, EndpointExemption::NONE, 2);
  const MutationResult published =
      fixture.runtime.publish_policy(policy, fixture.actor("conc-policy"));
  PD_CHECK_EQ(published.status, MutationStatus::APPLIED);
  return PublishedPolicy{published.policy.id, published.policy.generation};
}

ProofRequest request_for(const Pair& pair, const PublishedPolicy& policy) {
  ProofRequest request;
  request.policy = policy.id;
  request.policy_generation = policy.generation;
  request.paths.push_back(
      PathRef{PathId::parse(pair.first), PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(
      PathRef{PathId::parse(pair.second), PathAuthorityGeneration::from_value(1)});
  return request;
}

struct OutcomeCounts {
  std::atomic<std::uint64_t> applied{0};
  std::atomic<std::uint64_t> unchanged{0};
  std::atomic<std::uint64_t> idempotent{0};
  std::atomic<std::uint64_t> revalidation{0};
  std::atomic<std::uint64_t> other{0};
  std::atomic<std::uint64_t> calls{0};
};

void count_outcome(OutcomeCounts& counts, const MutationResult& result) {
  counts.calls.fetch_add(1, std::memory_order_relaxed);
  switch (result.status) {
    case MutationStatus::APPLIED:
      counts.applied.fetch_add(1, std::memory_order_relaxed);
      break;
    case MutationStatus::UNCHANGED:
      counts.unchanged.fetch_add(1, std::memory_order_relaxed);
      break;
    case MutationStatus::IDEMPOTENT:
      counts.idempotent.fetch_add(1, std::memory_order_relaxed);
      break;
    case MutationStatus::REVALIDATION_REQUIRED:
      counts.revalidation.fetch_add(1, std::memory_order_relaxed);
      break;
    default:
      counts.other.fetch_add(1, std::memory_order_relaxed);
      break;
  }
}

}  // namespace

PD_TEST(evaluators_and_a_topology_writer_never_leave_a_stale_proof_current) {
  pd_test::Fixture fixture;
  install_pairs(fixture, kPathPairs);
  const PublishedPolicy policy = publish_links_policy(fixture);

  const std::uint32_t thread_count = kEvaluatorThreads + 1;
  std::barrier gate(static_cast<std::ptrdiff_t>(thread_count));
  OutcomeCounts counts;
  Report reports[kEvaluatorThreads];
  std::atomic<std::uint64_t> advances{0};

  // The topology writer advances the served generation and immediately demotes
  // the revisions that bound the generation it moved past.
  std::thread topology_writer([&]() {
    gate.arrive_and_wait();
    for (std::uint32_t step = 0; step < kRounds; ++step) {
      const TopologyGeneration next = fixture.evidence.topology_generation().next();
      relabel_topology(fixture, kPathPairs, next);
      fixture.runtime.demote_topology_generation(next);
      advances.fetch_add(1, std::memory_order_relaxed);
    }
  });

  std::vector<std::thread> evaluators;
  evaluators.reserve(kEvaluatorThreads);
  for (std::uint32_t thread_index = 0; thread_index < kEvaluatorThreads; ++thread_index) {
    evaluators.emplace_back([&, thread_index]() {
      Report& report = reports[thread_index];
      gate.arrive_and_wait();
      for (std::uint32_t round = 0; round < kRounds; ++round) {
        for (std::uint32_t slot = 0; slot < kPairsPerThread; ++slot) {
          const std::uint32_t index = thread_index * kPairsPerThread + slot;
          const MutationResult result = fixture.runtime.evaluate(
              request_for(pair_at(index), policy),
              fixture.actor("conc-" + std::to_string(thread_index) + "-" + std::to_string(round) +
                            "-" + std::to_string(index)));
          count_outcome(counts, result);
          if (result.has_proof && result.proof.dependencies.topology_generation >
                                      fixture.evidence.topology_generation()) {
            report.bound_a_future_generation = true;
          }
        }
      }
      // Every evaluator also reads the registry while the writer is running.
      audit_registry(fixture.runtime, fixture.limits, report);
    });
  }
  for (std::thread& evaluator : evaluators) {
    evaluator.join();
  }
  topology_writer.join();

  PD_CHECK_EQ(advances.load(), std::uint64_t{kRounds});
  PD_CHECK_EQ(counts.calls.load(), std::uint64_t{kTotalCalls});
  PD_CHECK(counts.applied.load() > 0);
  PD_CHECK_EQ(counts.other.load(), std::uint64_t{0});
  PD_CHECK_EQ(counts.applied.load() + counts.unchanged.load() + counts.idempotent.load() +
                  counts.revalidation.load(),
              std::uint64_t{kTotalCalls});
  for (const Report& report : reports) {
    pd_test::check(report.violations == 0, "concurrent evaluator: " + report.first_violation,
                   __FILE__, __LINE__);
    pd_test::check(!report.counter_went_backwards, "a concurrent evaluator saw a counter rewind",
                   __FILE__, __LINE__);
    pd_test::check(!report.bound_a_future_generation,
                   "a committed revision bound a future topology generation", __FILE__, __LINE__);
    pd_test::check(report.snapshots > 0, "a concurrent evaluator audited no snapshot", __FILE__,
                   __LINE__);
  }

  // A final demotion closes the window the writer opened last, so nothing stale
  // may remain current afterwards.
  fixture.runtime.demote_topology_generation(fixture.evidence.topology_generation());
  const TopologyGeneration observed = fixture.evidence.topology_generation();
  const FailureDomainGeneration domains = fixture.evidence.generation();
  const DiversityRuntime::QueryResult all = fixture.runtime.all_proofs();
  PD_CHECK(all.total > 0);
  for (const DiversityProofId& id : all.proofs) {
    const std::optional<DiversityProof> proof = fixture.runtime.proof(id);
    PD_REQUIRE(proof.has_value());
    std::string why;
    PD_CHECK(revision_is_well_formed(*proof, why));
    if (proof->current()) {
      // A revision that is still current must bind exactly the generations the
      // authorities serve now; anything else would be a lost invalidation.
      PD_CHECK_EQ(proof->dependencies.topology_generation, observed);
      PD_CHECK_EQ(proof->dependencies.failure_domain_generation, domains);
      PD_CHECK_EQ(proof->dependencies.policy_generation,
                  fixture.runtime.policy_generation(proof->request.policy));
      for (const PathAuthorityBinding& binding : proof->dependencies.paths) {
        const std::optional<PathAuthorityGeneration> current =
            fixture.evidence.current_generation(binding.path);
        PD_CHECK(current.has_value() && *current == binding.generation);
      }
    } else {
      PD_CHECK(proof->dependencies.topology_generation <= observed);
    }
    // Every reverse index still resolves the committed revision.
    const auto resolves = [&](const DiversityRuntime::QueryResult& result) {
      for (const DiversityProofId& candidate : result.proofs) {
        if (candidate == id) {
          return true;
        }
      }
      return false;
    };
    PD_CHECK(resolves(fixture.runtime.proofs_for_policy(proof->request.policy)));
    PD_CHECK(resolves(fixture.runtime.proofs_for_boot(proof->provenance.boot)));
    for (const PathRef& reference : proof->request.paths) {
      PD_CHECK(resolves(fixture.runtime.proofs_for_path(reference.path)));
    }
    for (const EntityRef& entity : proof->dependencies.topology_entities) {
      PD_CHECK(resolves(fixture.runtime.proofs_for_entity(entity)));
    }
  }

  // The counters describe exactly what the threads observed.
  const RuntimeStats stats = fixture.runtime.stats();
  const std::string histogram =
      " evaluations=" + std::to_string(stats.evaluations) + " applied=" +
      std::to_string(counts.applied.load()) + " unchanged=" +
      std::to_string(counts.unchanged.load()) + " idempotent=" +
      std::to_string(counts.idempotent.load()) + " revalidation=" +
      std::to_string(counts.revalidation.load()) + " other=" +
      std::to_string(counts.other.load()) + " calls=" + std::to_string(counts.calls.load());
  pd_test::check(stats.evaluations == std::uint64_t{kTotalCalls},
                 std::string("stats.evaluations == kTotalCalls") + histogram, __FILE__,
                 __LINE__);
  // A late result is still recorded as an auditable revision, so both the
  // applied and the drift-rejected evaluations count as commits.
  pd_test::check(stats.commits == counts.applied.load() + counts.revalidation.load(),
                 std::string("stats.commits == applied + revalidation") + histogram, __FILE__,
                 __LINE__);
  pd_test::check(stats.unchanged_revalidations == counts.unchanged.load(),
                 std::string("stats.unchanged == unchanged") + histogram, __FILE__, __LINE__);
  pd_test::check(stats.idempotent_replays == counts.idempotent.load(),
                 std::string("stats.idempotent == idempotent") + histogram, __FILE__, __LINE__);
  // A drift that ends in an unchanged revision is reported as UNCHANGED while
  // still counting as a watermark rejection, so the rejection count is an upper
  // bound for the results that were actually reported as revalidation.
  PD_CHECK(stats.watermark_rejections >= counts.revalidation.load());
  // Deterministic invalidation: a revision committed at the generation the
  // authorities serve now must stop being current the moment that generation
  // moves past it. The concurrent writers are gone by this point, so this part
  // of the assertion never depends on scheduling.
  const MutationResult fresh = fixture.runtime.evaluate(
      request_for(pair_at(0), policy), fixture.actor("conc-final"));
  PD_REQUIRE(fresh.has_proof);
  const std::uint64_t demotions_before = fixture.runtime.stats().demotions;
  const TopologyGeneration next = fixture.evidence.topology_generation().next();
  relabel_topology(fixture, kPathPairs, next);
  fixture.runtime.demote_topology_generation(next);
  PD_CHECK(fixture.runtime.stats().demotions > demotions_before);
  const std::optional<DiversityProof> invalidated = fixture.runtime.proof(fresh.proof.id);
  PD_REQUIRE(invalidated.has_value());
  PD_CHECK(!invalidated->current());
  PD_CHECK_EQ(invalidated->currentness, Currentness::STALE_TOPOLOGY);
  Report final_report;
  audit_registry(fixture.runtime, fixture.limits, final_report);
  PD_CHECK_EQ(final_report.violations, std::uint64_t{0});
}

PD_TEST(readers_never_observe_a_partially_updated_registry) {
  pd_test::Fixture fixture;
  install_pairs(fixture, kPathPairs);
  const PublishedPolicy policy = publish_links_policy(fixture);

  const std::uint32_t reader_count = 3;
  const std::uint32_t participants = reader_count + 2;
  std::barrier gate(static_cast<std::ptrdiff_t>(participants));
  // The rendezvous after the first commit is what makes "a reader observed a
  // committed revision while the writers were still running" deterministic
  // instead of a matter of scheduling luck: no thread can leave it before every
  // reader has caught the first committed revision.
  std::barrier first_commit_gate(static_cast<std::ptrdiff_t>(participants));
  std::atomic<bool> writers_done{false};
  Report reports[reader_count];

  std::vector<std::thread> readers;
  readers.reserve(reader_count);
  for (std::uint32_t index = 0; index < reader_count; ++index) {
    readers.emplace_back([&, index]() {
      Report& report = reports[index];
      gate.arrive_and_wait();
      // A bounded spin, never a sleep. The bound is a hang guard, not a wait:
      // the committer publishes one revision unconditionally before the gate.
      std::uint64_t spins = 0;
      while (report.proofs_seen == 0 && spins < 1000000) {
        ++spins;
        audit_registry(fixture.runtime, fixture.limits, report);
      }
      report.observed_while_writers_ran = report.proofs_seen > 0;
      first_commit_gate.arrive_and_wait();
      std::uint64_t iterations = 0;
      while (iterations < 2000000) {
        ++iterations;
        audit_registry(fixture.runtime, fixture.limits, report);
        if (writers_done.load(std::memory_order_acquire) && report.proofs_seen > 0) {
          break;
        }
      }
    });
  }

  std::thread topology_writer([&]() {
    gate.arrive_and_wait();
    first_commit_gate.arrive_and_wait();
    for (std::uint32_t step = 0; step < kRounds; ++step) {
      const TopologyGeneration next = fixture.evidence.topology_generation().next();
      relabel_topology(fixture, kPathPairs, next);
      fixture.runtime.demote_topology_generation(next);
    }
  });
  std::thread committer([&]() {
    gate.arrive_and_wait();
    const MutationResult first = fixture.runtime.evaluate(
        request_for(pair_at(0), policy), fixture.actor("conc-commit-first"));
    (void)first;
    first_commit_gate.arrive_and_wait();
    for (std::uint32_t round = 0; round < kRounds; ++round) {
      for (std::uint32_t index = 0; index < kPathPairs; ++index) {
        const MutationResult result = fixture.runtime.evaluate(
            request_for(pair_at(index), policy),
            fixture.actor("conc-commit-" + std::to_string(round) + "-" + std::to_string(index)));
        (void)result;
      }
    }
    writers_done.store(true, std::memory_order_release);
  });

  for (std::thread& reader : readers) {
    reader.join();
  }
  topology_writer.join();
  committer.join();

  PD_CHECK(writers_done.load());
  PD_CHECK_EQ(fixture.runtime.proof_count(), std::size_t{kPathPairs});
  for (const Report& report : reports) {
    pd_test::check(report.snapshots > 0, "a reader never completed a snapshot", __FILE__,
                   __LINE__);
    pd_test::check(report.proofs_seen > 0, "a reader never observed a committed revision",
                   __FILE__, __LINE__);
    pd_test::check(report.observed_while_writers_ran,
                   "a reader observed no revision while the writers were running", __FILE__,
                   __LINE__);
    pd_test::check(report.violations == 0, "a reader observed an inconsistent registry: " +
                                               report.first_violation,
                   __FILE__, __LINE__);
    pd_test::check(!report.counter_went_backwards, "a reader saw a counter rewind", __FILE__,
                   __LINE__);
  }
  Report final_report;
  audit_registry(fixture.runtime, fixture.limits, final_report);
  PD_CHECK_EQ(final_report.violations, std::uint64_t{0});
}

PD_TEST(concurrent_replay_of_one_attempt_commits_exactly_once) {
  pd_test::Fixture fixture;
  install_pairs(fixture, 1);
  const PublishedPolicy policy = publish_links_policy(fixture);
  const ProofRequest request = request_for(pair_at(0), policy);

  const std::uint32_t thread_count = 6;
  std::barrier gate(static_cast<std::ptrdiff_t>(thread_count));
  std::vector<MutationStatus> statuses(thread_count, MutationStatus::MALFORMED);

  std::vector<std::thread> threads;
  threads.reserve(thread_count);
  for (std::uint32_t index = 0; index < thread_count; ++index) {
    threads.emplace_back([&, index]() {
      gate.arrive_and_wait();
      // Every thread presents the exact same attempt: the mutation may happen
      // once and must be reported as a replay to everyone else.
      statuses[index] = fixture.runtime.evaluate(request, fixture.actor("conc-shared-attempt")).status;
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }

  std::uint64_t applied = 0;
  std::uint64_t idempotent = 0;
  for (MutationStatus status : statuses) {
    if (status == MutationStatus::APPLIED) {
      ++applied;
    } else if (status == MutationStatus::IDEMPOTENT) {
      ++idempotent;
    }
  }
  PD_CHECK_EQ(applied, std::uint64_t{1});
  PD_CHECK_EQ(idempotent, static_cast<std::uint64_t>(thread_count) - 1);
  PD_CHECK_EQ(fixture.runtime.proof_count(), std::size_t{1});
  const std::optional<DiversityProof> proof = fixture.runtime.proof(proof_identity(request));
  PD_REQUIRE(proof.has_value());
  PD_CHECK_EQ(proof->generation.value(), std::uint64_t{1});
  const RuntimeStats stats = fixture.runtime.stats();
  PD_CHECK_EQ(stats.commits, std::uint64_t{1});
  PD_CHECK_EQ(stats.idempotent_replays, static_cast<std::uint64_t>(thread_count) - 1);
  // A replayed attempt is refused in phase one, so only the winning call ever
  // reached evaluation.
  PD_CHECK_EQ(stats.evaluations, std::uint64_t{1});
  Report report;
  audit_registry(fixture.runtime, fixture.limits, report);
  PD_CHECK_EQ(report.violations, std::uint64_t{0});
}

PD_TEST(concurrent_policy_publication_never_loses_a_generation) {
  pd_test::Fixture fixture;
  const std::uint32_t thread_count = 6;
  const std::uint32_t updates = 8;
  std::barrier gate(static_cast<std::ptrdiff_t>(thread_count));
  std::barrier round_gate(static_cast<std::ptrdiff_t>(thread_count));
  std::atomic<std::uint64_t> applied{0};
  std::atomic<std::uint64_t> conflicts{0};

  // The identity is established first so every thread races on its generation.
  DiversityPolicy seed = pd_test::make_policy(
      "dpol-concurrent-update", {DiversityClass::LINK_DISJOINT}, EndpointExemption::NONE, 2);
  const MutationResult established = fixture.runtime.publish_policy(seed, fixture.actor("conc-seed"));
  PD_CHECK_EQ(established.status, MutationStatus::APPLIED);

  std::vector<std::thread> threads;
  threads.reserve(thread_count);
  for (std::uint32_t index = 0; index < thread_count; ++index) {
    threads.emplace_back([&, index]() {
      gate.arrive_and_wait();
      for (std::uint32_t update = 0; update < updates; ++update) {
        // Every thread reads the same generation before the round gate, so at
        // most one publish per round can be accepted. A lost update would show
        // up as a final generation below one plus the accepted count.
        ActingAuthority authority =
            fixture.actor("conc-update-" + std::to_string(index) + "-" + std::to_string(update));
        authority.expected_policy_generation =
            fixture.runtime.policy_generation(established.policy.id);
        DiversityPolicy policy = seed;
        policy.description =
            "concurrent update " + std::to_string(index) + "-" + std::to_string(update);
        round_gate.arrive_and_wait();
        const MutationResult result = fixture.runtime.publish_policy(policy, authority);
        if (result.status == MutationStatus::APPLIED) {
          applied.fetch_add(1, std::memory_order_relaxed);
        } else {
          conflicts.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }

  PD_CHECK_EQ(applied.load() + conflicts.load(),
              static_cast<std::uint64_t>(thread_count) * updates);
  PD_CHECK_EQ(applied.load(), std::uint64_t{updates});
  PD_CHECK_EQ(conflicts.load(), static_cast<std::uint64_t>(thread_count - 1) * updates);
  const std::optional<DiversityPolicy> stored = fixture.runtime.policy(established.policy.id);
  PD_REQUIRE(stored.has_value());
  // Every accepted update advanced the generation by exactly one step from the
  // value it expected, so no accepted write was lost and none was invented.
  PD_CHECK_EQ(stored->generation.value(), std::uint64_t{1} + applied.load());
  PD_CHECK_EQ(fixture.runtime.policy_count(), std::size_t{1});
  PD_CHECK(!stored->description.empty());
  Report report;
  audit_registry(fixture.runtime, fixture.limits, report);
  PD_CHECK_EQ(report.violations, std::uint64_t{0});
}

PD_TEST_MAIN()
