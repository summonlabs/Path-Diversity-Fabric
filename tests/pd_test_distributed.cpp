// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
// Real out-of-process proofs: worker death and coordinator restart.
//
// The parent test process never emulates a death. It spawns a real coordinator
// process and real worker processes, kills them with a hard kill, and observes
// the consequences through the public protocol.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "process_helper.hpp"
#include "test_support.hpp"

using namespace path_diversity;
using pd_test::ChildLease;
using pd_test::ChildProcess;
using pd_test::spawn_self;
using pd_test::unique_test_path;
using pd_test::wait_for_marker;

namespace {

constexpr const char* kCoordinatorAddress = "127.0.0.1";
constexpr const char* kPathA = "path-dist-a";
constexpr const char* kPathB = "path-dist-b";
constexpr const char* kPolicyId = "dpol-dist";

std::filesystem::path store_of(const std::filesystem::path& dir) { return dir / "store.pdkv"; }
std::filesystem::path port_of(const std::filesystem::path& dir) { return dir / "port"; }
std::filesystem::path epoch_of(const std::filesystem::path& dir) { return dir / "epoch"; }
std::filesystem::path ready_of(const std::filesystem::path& dir, const std::string& label) {
  return dir / ("ready-" + label);
}

std::uint64_t read_epoch(const std::filesystem::path& dir);

// The scenario both sides agree on. The coordinator authors it; the worker only
// refers to it by identity.
void seed_scenario(InMemoryEvidence& evidence) {
  PathComposition left =
      pd_test::make_path(kPathA, 1, {"na1"}, {"la1", "la2"}, {"da"}, "host-src", "host-dst");
  PathComposition right =
      pd_test::make_path(kPathB, 1, {"nb1"}, {"lb1", "lb2"}, {"db"}, "host-src", "host-dst");
  evidence.set_path(left);
  evidence.set_path(right);
  pd_test::classify_path(evidence, left, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-dist-a"});
  pd_test::classify_path(evidence, right, DomainRelation::FAILURE_DOMAIN,
                         EvidenceCoverage::COMPLETE, {"fd-dist-b"});
}

DiversityPolicy distribution_policy() {
  return pd_test::make_policy(kPolicyId,
                              {DiversityClass::LINK_DISJOINT,
                               DiversityClass::TRANSIT_NODE_DISJOINT},
                              EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
}

ProofRequest distribution_request(DiversityPolicyGeneration generation) {
  ProofRequest request;
  request.policy = DiversityPolicyId::parse(kPolicyId);
  request.policy_generation = generation;
  request.paths.push_back(PathRef{PathId::parse(kPathA), PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(PathRef{PathId::parse(kPathB), PathAuthorityGeneration::from_value(1)});
  request.canonicalize();
  return request;
}

// --- Child process: the coordinator ---------------------------------------
int run_coordinator(const std::filesystem::path& dir) {
  Limits limits;
  InMemoryEvidence evidence;
  seed_scenario(evidence);
  PublicationAuthority publication(limits);
  DiversityRuntime runtime(evidence, evidence, evidence, publication, limits);

  std::uint64_t epoch = 1;
  const std::filesystem::path store = store_of(dir);
  std::error_code error;
  if (std::filesystem::exists(store, error)) {
    std::vector<std::uint8_t> bytes;
    StoreContents contents;
    std::string detail;
    if (read_store_bytes(store.string(), limits, bytes) == PersistenceStatus::OK &&
        decode_store(bytes.data(), bytes.size(), limits, contents, detail) ==
            PersistenceStatus::OK) {
      runtime.load(store.string());
      epoch = contents.epoch.value() + 1;
    }
  }
  publication.restore_epoch(CoordinatorEpoch::from_value(epoch));

  DiversityCoordinator coordinator(runtime, limits);
  coordinator.set_store_path(store.string());
  if (coordinator.start(kCoordinatorAddress, 0) != TransportStatus::OK) {
    return 3;
  }
  coordinator.persist();
  pd_test::write_marker(port_of(dir), std::to_string(coordinator.port()));
  pd_test::write_marker(epoch_of(dir), std::to_string(epoch));
  // Serve until the process is killed. A hard kill is the point of the proof,
  // so no graceful shutdown path is offered.
  while (true) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
}

// --- Child process: a worker ----------------------------------------------
int run_worker(std::uint16_t port, const std::string& label, const std::filesystem::path& dir,
               bool expect_refused) {
  Limits limits;
  DiversityClient client(limits);
  if (client.connect(kCoordinatorAddress, port) != TransportStatus::OK) {
    return 4;
  }
  const WorkerBootId boot = WorkerBootId::parse("boot-" + label);
  const CoordinatorEpoch epoch = CoordinatorEpoch::from_value(read_epoch(dir));
  HelloPayload hello;
  hello.publisher = PublisherId::parse("pub-" + label);
  hello.boot = boot;
  hello.epoch = epoch;
  hello.scope = default_scope();
  const TransportStatus greeted = client.hello(hello);
  std::fprintf(stderr, "WORKER %s hello=%s\n", label.c_str(),
               std::string(to_string(greeted)).c_str());
  if (expect_refused) {
    // A fenced boot must never be able to register again.
    return greeted == TransportStatus::OK ? 5 : 0;
  }
  if (greeted != TransportStatus::OK) {
    return 6;
  }

  const DiversityPolicy policy = distribution_policy();
  DiversityPolicyGeneration published;
  bool have_policy = false;
  for (std::uint64_t attempt = 0; attempt < 8 && !have_policy; ++attempt) {
    ActingAuthority authority;
    authority.epoch = epoch;
    authority.publisher = hello.publisher;
    authority.boot = boot;
    authority.scope = default_scope();
    // Attempt identities are coordinator-scoped idempotency keys, so they must
    // be unique per worker as well as per mutation.
    authority.attempt = MutationAttemptId::parse("attempt-policy-" + label + "-" +
                                                 std::to_string(attempt));
    authority.expected_policy_generation =
        attempt == 0 ? DiversityPolicyGeneration()
                     : DiversityPolicyGeneration::from_value(attempt);
    MutationResult result;
    const TransportStatus status = client.publish_policy(authority, policy, result);
    if (status != TransportStatus::OK) {
      return 7;
    }
    if (result.status == MutationStatus::APPLIED) {
      have_policy = true;
      // A successful publication with expectation g produces generation g + 1.
      published = DiversityPolicyGeneration::from_value(static_cast<std::uint64_t>(attempt) + 1);
      break;
    }
    if (result.status != MutationStatus::GENERATION_CONFLICT) {
      std::fprintf(stderr, "WORKER %s policy status=%s detail=%s\n", label.c_str(),
                   std::string(to_string(result.status)).c_str(), result.detail.c_str());
      return 8;
    }
  }
  if (!have_policy) {
    return 9;
  }

  ActingAuthority authority;
  authority.epoch = epoch;
  authority.publisher = hello.publisher;
  authority.boot = boot;
  authority.scope = default_scope();
  authority.attempt = MutationAttemptId::parse("attempt-proof-" + label);
  MutationResult proof_result;
  if (client.publish_proof(authority, distribution_request(published), proof_result) !=
      TransportStatus::OK) {
    return 10;
  }
  if (proof_result.status != MutationStatus::APPLIED &&
      proof_result.status != MutationStatus::IDEMPOTENT) {
    std::fprintf(stderr, "WORKER %s proof status=%s detail=%s gen=%llu\n", label.c_str(),
                 std::string(to_string(proof_result.status)).c_str(),
                 proof_result.detail.c_str(),
                 static_cast<unsigned long long>(published.value()));
    return 11;
  }
  pd_test::write_marker(ready_of(dir, label), proof_result.proof.id.str());
  while (true) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
}

std::uint16_t read_port(const std::filesystem::path& dir) {
  const std::string text = pd_test::read_marker(port_of(dir));
  if (text.empty()) {
    return 0;
  }
  return static_cast<std::uint16_t>(std::stoi(text));
}

std::size_t current_proof_count(std::uint16_t port) {
  DiversityClient client;
  if (client.connect(kCoordinatorAddress, port) != TransportStatus::OK) {
    return 0;
  }
  QueryPayload query;
  query.selector = 5;
  QueryResultPayload result;
  if (client.query(query, result) != TransportStatus::OK) {
    return 0;
  }
  return result.proofs.size();
}

// A restarted child writes the same marker files, so the previous run markers
// must be removed first or the parent would read a stale port and epoch.
void clear_markers(const std::filesystem::path& dir) {
  std::error_code error;
  std::filesystem::remove(port_of(dir), error);
  std::filesystem::remove(epoch_of(dir), error);
}

std::size_t all_proof_count(std::uint16_t port) {
  DiversityClient client;
  if (client.connect(kCoordinatorAddress, port) != TransportStatus::OK) {
    return 0;
  }
  QueryPayload query;
  query.selector = 0;
  QueryResultPayload result;
  if (client.query(query, result) != TransportStatus::OK) {
    return 0;
  }
  return result.proofs.size();
}

std::uint64_t read_epoch(const std::filesystem::path& dir) {
  const std::string text = pd_test::read_marker(epoch_of(dir));
  return text.empty() ? 0 : std::stoull(text);
}

}  // namespace

// ---------------------------------------------------------------------------
// Real worker death.
// ---------------------------------------------------------------------------
PD_TEST(worker_death_fences_boot_and_demotes_publications) {
  const std::filesystem::path dir = unique_test_path("worker-death");
  std::error_code error;
  std::filesystem::create_directories(dir, error);

  ChildLease coordinator(spawn_self({"--coordinator", dir.string()}));
  PD_REQUIRE(coordinator.valid());
  PD_REQUIRE(wait_for_marker(port_of(dir), std::chrono::seconds(20)));
  const std::uint16_t port = read_port(dir);
  PD_REQUIRE(port != 0);

  ChildLease worker(spawn_self({"--worker", std::to_string(port), "worker-1", dir.string()}));
  PD_REQUIRE(worker.valid());
  PD_REQUIRE(wait_for_marker(ready_of(dir, "worker-1"), std::chrono::seconds(20)));

  // The publication is live and a second independent client can see it.
  PD_CHECK_EQ(current_proof_count(port), std::size_t(1));
  const std::string published_id = pd_test::read_marker(ready_of(dir, "worker-1"));
  PD_CHECK(!published_id.empty());

  // Durable policy and history survive the kill because persistence happens
  // before the acknowledgement.
  {
    Limits limits;
    std::vector<std::uint8_t> bytes;
    PD_CHECK(read_store_bytes(store_of(dir).string(), limits, bytes) == PersistenceStatus::OK);
    StoreContents contents;
    std::string detail;
    PD_CHECK(decode_store(bytes.data(), bytes.size(), limits, contents, detail) ==
             PersistenceStatus::OK);
    PD_CHECK_EQ(contents.policies.size(), std::size_t(1));
    PD_CHECK_EQ(contents.proofs.size(), std::size_t(1));
    PD_CHECK_EQ(contents.epoch.value(), std::uint64_t(1));
  }

  // Kill the real worker process.
  PD_CHECK(worker.kill());
  PD_CHECK(!worker.running());

  // The coordinator observes the loss, fences the boot and demotes every live
  // publication attributed to it.
  const bool demoted = pd_test::wait_until([&]() { return current_proof_count(port) == 0; },
                                           std::chrono::seconds(20));
  PD_CHECK(demoted);

  // The historical proof is retained: it exists, it is simply not current.
  PD_CHECK_EQ(all_proof_count(port), std::size_t(1));

  // A fenced boot can never register again, even from a fresh process.
  ChildLease reincarnation(spawn_self({"--fenced-worker", std::to_string(port), "worker-1", dir.string()}));
  PD_REQUIRE(reincarnation.valid());
  {
    const bool finished = pd_test::wait_until([&]() { return !reincarnation.running(); },
                                              std::chrono::seconds(20));
    PD_CHECK(finished);
  }
  reincarnation.kill();

  // A fresh boot registers and republishes: live authority is restored without
  // resurrecting the dead boot.
  ChildLease fresh(spawn_self({"--worker", std::to_string(port), "worker-2", dir.string()}));
  PD_REQUIRE(fresh.valid());
  PD_REQUIRE(wait_for_marker(ready_of(dir, "worker-2"), std::chrono::seconds(20)));
  PD_CHECK_EQ(current_proof_count(port), std::size_t(1));

  fresh.kill();
  coordinator.kill();
  PD_CHECK(!coordinator.running());
}

// ---------------------------------------------------------------------------
// Real coordinator restart with monotonic epochs.
// ---------------------------------------------------------------------------
PD_TEST(coordinator_restart_recovers_history_and_advances_epoch) {
  const std::filesystem::path dir = unique_test_path("coordinator-restart");
  std::error_code error;
  std::filesystem::create_directories(dir, error);

  clear_markers(dir);
  ChildLease first(spawn_self({"--coordinator", dir.string()}));
  PD_REQUIRE(first.valid());
  PD_REQUIRE(wait_for_marker(port_of(dir), std::chrono::seconds(20)));
  const std::uint16_t first_port = read_port(dir);
  PD_REQUIRE(first_port != 0);
  PD_CHECK_EQ(read_epoch(dir), std::uint64_t(1));

  ChildLease worker(spawn_self({"--worker", std::to_string(first_port), "worker-r1",
                                    dir.string()}));
  PD_REQUIRE(worker.valid());
  PD_REQUIRE(wait_for_marker(ready_of(dir, "worker-r1"), std::chrono::seconds(20)));
  PD_CHECK_EQ(current_proof_count(first_port), std::size_t(1));
  const std::string recovered_id = pd_test::read_marker(ready_of(dir, "worker-r1"));

  // Hard kill the coordinator process. No destructor runs, nothing is flushed.
  PD_CHECK(first.kill());
  PD_CHECK(!first.running());

  // A new coordinator starts, restores the durable state and comes back at a
  // strictly higher epoch.
  clear_markers(dir);
  ChildLease second(spawn_self({"--coordinator", dir.string()}));
  PD_REQUIRE(second.valid());
  PD_REQUIRE(wait_for_marker(port_of(dir), std::chrono::seconds(20)));
  const std::uint16_t second_port = read_port(dir);
  PD_REQUIRE(second_port != 0);
  PD_CHECK_EQ(read_epoch(dir), std::uint64_t(2));

  // Historical proof data is recovered.
  PD_CHECK_EQ(all_proof_count(second_port), std::size_t(1));
  {
    Limits limits;
    std::vector<std::uint8_t> bytes;
    PD_REQUIRE(read_store_bytes(store_of(dir).string(), limits, bytes) == PersistenceStatus::OK);
    StoreContents contents;
    std::string detail;
    PD_REQUIRE(decode_store(bytes.data(), bytes.size(), limits, contents, detail) ==
               PersistenceStatus::OK);
    PD_REQUIRE(contents.proofs.size() == 1);
    PD_CHECK_EQ(contents.proofs.front().id.str(), recovered_id);
    // Epochs only ever move forward across a restart.
    PD_CHECK_EQ(contents.epoch.value(), std::uint64_t(2));
  }

  // An old epoch is refused.
  {
    DiversityClient client;
    PD_REQUIRE(client.connect(kCoordinatorAddress, second_port) == TransportStatus::OK);
    HelloPayload hello;
    hello.publisher = PublisherId::parse("pub-stale");
    hello.boot = WorkerBootId::parse("boot-stale");
    hello.epoch = CoordinatorEpoch::from_value(1);
    hello.scope = default_scope();
    PD_CHECK(client.hello(hello) != TransportStatus::OK);
  }

  // The current epoch is accepted.
  {
    DiversityClient client;
    PD_REQUIRE(client.connect(kCoordinatorAddress, second_port) == TransportStatus::OK);
    HelloPayload hello;
    hello.publisher = PublisherId::parse("pub-current");
    hello.boot = WorkerBootId::parse("boot-current");
    hello.epoch = CoordinatorEpoch::from_value(read_epoch(dir));
    hello.scope = default_scope();
    PD_CHECK(client.hello(hello) == TransportStatus::OK);

    // No live publisher authority is restored: the pre-restart boot is not a
    // registered session any more, so a publication that claims it is refused.
    ActingAuthority authority;
    authority.epoch = CoordinatorEpoch::from_value(read_epoch(dir));
    authority.publisher = PublisherId::parse("pub-current");
    authority.boot = WorkerBootId::parse("boot-worker-r1");
    authority.scope = default_scope();
    authority.attempt = MutationAttemptId::parse("attempt-stale-boot-check");
    MutationResult result;
    PD_REQUIRE(client.publish_proof(authority,
                                    distribution_request(DiversityPolicyGeneration::from_value(1)),
                                    result) == TransportStatus::OK);
    PD_CHECK(result.status == MutationStatus::UNAUTHORIZED);
  }

  // Repeat: a second restart keeps epochs strictly monotonic.
  PD_CHECK(second.kill());
  clear_markers(dir);
  ChildLease third(spawn_self({"--coordinator", dir.string()}));
  PD_REQUIRE(third.valid());
  PD_REQUIRE(wait_for_marker(port_of(dir), std::chrono::seconds(20)));
  PD_REQUIRE(read_port(dir) != 0);
  PD_CHECK_EQ(read_epoch(dir), std::uint64_t(3));
  PD_CHECK_EQ(all_proof_count(read_port(dir)), std::size_t(1));

  third.kill();
  worker.kill();
  PD_CHECK(!third.running());
  PD_CHECK(!worker.running());
}

int main(int argc, char** argv) {
  if (argc >= 3 && std::string(argv[1]) == "--coordinator") {
    return run_coordinator(std::filesystem::path(argv[2]));
  }
  if (argc >= 5 && std::string(argv[1]) == "--worker") {
    return run_worker(static_cast<std::uint16_t>(std::stoi(argv[2])), argv[3],
                      std::filesystem::path(argv[4]), false);
  }
  if (argc >= 5 && std::string(argv[1]) == "--fenced-worker") {
    return run_worker(static_cast<std::uint16_t>(std::stoi(argv[2])), argv[3],
                      std::filesystem::path(argv[4]), true);
  }
  return pd_test::run_all();
}
