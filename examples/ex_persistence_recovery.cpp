// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Persistence round trip and conservative recovery. A store reloads exactly; a
// copy with one flipped byte is refused with INTEGRITY_FAILURE, and the runtime
// that refuses it keeps exactly the state it already had.

#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <vector>

#include "example_support.hpp"

namespace {

using namespace example;

std::vector<PathComposition> disjoint_paths() {
  std::vector<PathComposition> paths;
  paths.push_back(make_path("path-a", "node-a1", "node-d1", {"node-b"}, {"link-a1b", "link-bd1"}));
  paths.push_back(make_path("path-b", "node-a2", "node-d2", {"node-c"}, {"link-a2c", "link-cd2"}));
  return paths;
}

// One fresh runtime over the same synthetic topology.
struct Instance {
  Instance() : evidence(), publication(), runtime(evidence, evidence, evidence, publication) {}
  Instance(const Instance&) = delete;
  Instance& operator=(const Instance&) = delete;
  InMemoryEvidence evidence;
  PublicationAuthority publication;
  DiversityRuntime runtime;
};

// Flips one bit in the middle of a file, clear of the magic and the trailer.
bool flip_middle_byte(const std::string& path, std::size_t& offset) {
  std::ifstream input(path, std::ios::binary);
  const std::vector<char> bytes((std::istreambuf_iterator<char>(input)),
                                std::istreambuf_iterator<char>());
  input.close();
  if (bytes.size() < 64) {
    return false;
  }
  std::vector<char> altered = bytes;
  offset = altered.size() / 2;
  altered[offset] = static_cast<char>(altered[offset] ^ 0x01);
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(altered.data(), static_cast<std::streamsize>(altered.size()));
  output.close();
  return output.good();
}

}  // namespace

int main() {
  Reporter report("ex_persistence_recovery");
  Harness harness;

  const std::vector<PathComposition> paths = disjoint_paths();
  for (const PathComposition& composition : paths) {
    harness.evidence.set_path(composition);
  }

  PolicySpec spec;
  spec.id = "pol-persistence";
  spec.classes = {DiversityClass::LINK_DISJOINT, DiversityClass::TRANSIT_NODE_DISJOINT};
  const MutationResult published = harness.publish(spec, "publish-policy");
  report.check_name(published.status, "APPLIED", "the policy was published");
  if (!published.has_policy) {
    return report.finish();
  }
  const ProofRequest request = harness.request(published.policy.id, paths);
  const MutationResult committed = harness.runtime.evaluate(request, harness.authority("prove"));
  report.check_name(committed.status, "APPLIED", "the proof committed");
  if (!committed.has_proof) {
    return report.finish();
  }
  const DiversityProof original = committed.proof;
  const std::string original_digest = original.semantic_digest.hex();
  report.field("proof", original.id.str() + "@g" + std::to_string(original.generation.value()));

  const std::string store = scratch_path("ex-persistence-recovery.store");
  report.check_name(harness.runtime.save(store), "OK", "the runtime was written durably");

  Instance reloaded;
  for (const PathComposition& composition : paths) {
    reloaded.evidence.set_path(composition);
  }
  report.check_name(reloaded.runtime.load(store), "OK", "the store reloaded into a fresh runtime");
  report.check_equal(reloaded.runtime.proof_count(), std::size_t{1},
                     "the round trip restored exactly one proof");
  const std::optional<DiversityProof> restored = reloaded.runtime.proof(original.id);
  report.check(restored.has_value(), "the round trip restored the proof identity");
  if (!restored.has_value()) {
    return report.finish();
  }
  report.field("restored outcome", std::string(to_string(restored->outcome)));
  report.check_name(restored->outcome, "PROVEN_DIVERSE", "the round trip kept the result");
  report.check_equal(restored->semantic_digest.hex(), original_digest,
                     "the round trip kept the semantic identity");
  report.check_equal(restored->generation.value(), original.generation.value(),
                     "the round trip kept the revision");

  const std::string corrupt = scratch_path("ex-persistence-recovery-corrupt.store");
  std::error_code error;
  std::filesystem::copy_file(store, corrupt, std::filesystem::copy_options::overwrite_existing,
                             error);
  report.check(!error, "a copy of the store was prepared");
  std::size_t offset = 0;
  report.check(flip_middle_byte(corrupt, offset), "one bit was flipped in the middle of the copy");
  report.field("flipped byte offset", offset);

  Instance live;
  for (const PathComposition& composition : paths) {
    live.evidence.set_path(composition);
  }
  report.check_name(live.runtime.load(store), "OK", "the live runtime loaded the intact store");
  const std::size_t proofs_before = live.runtime.proof_count();
  const std::optional<DiversityProof> before = live.runtime.proof(original.id);
  report.check(before.has_value(), "the live runtime holds the proof");
  if (!before.has_value()) {
    return report.finish();
  }
  const std::string digest_before = before->semantic_digest.hex();
  report.check_name(live.runtime.load(corrupt), "INTEGRITY_FAILURE",
                    "a store with a flipped byte is refused");
  report.check_equal(live.runtime.proof_count(), proofs_before,
                     "the refusing runtime kept its proof registry");
  const std::optional<DiversityProof> after = live.runtime.proof(original.id);
  report.check(after.has_value(), "the live proof is still stored");
  if (after.has_value()) {
    report.check_equal(after->semantic_digest.hex(), digest_before,
                       "the live revision is unchanged by the refused load");
    report.check_name(after->outcome, "PROVEN_DIVERSE",
                      "the live result is unchanged by the refused load");
  }

  Instance empty;
  report.check_name(empty.runtime.load(corrupt), "INTEGRITY_FAILURE",
                    "a fresh runtime refuses the corrupt store as well");
  report.check_equal(empty.runtime.proof_count(), std::size_t{0},
                     "the refusing runtime holds no partial state");

  Instance again;
  for (const PathComposition& composition : paths) {
    again.evidence.set_path(composition);
  }
  report.check_name(again.runtime.load(store), "OK",
                    "the intact store is unaffected by the corrupted copy");
  report.check_equal(again.runtime.proof_count(), std::size_t{1},
                     "the intact store still holds its proof");

  return report.finish();
}
