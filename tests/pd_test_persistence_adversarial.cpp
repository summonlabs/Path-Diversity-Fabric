// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Adversarial store coverage. Every case here hands the loader a file it must
// refuse, and asserts the exact refusal. Nothing is repaired, nothing is
// defaulted and no rejected decode is ever treated as a store.

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

constexpr char kStoreMagic[8] = {'P', 'D', 'F', 'S', 'T', 'O', 'R', 'E'};

// Every refusal this suite observes, so the last case can prove that the
// rejection taxonomy is actually distinct rather than one status reused.
std::vector<std::pair<std::string, PersistenceStatus>>& ledger() {
  static std::vector<std::pair<std::string, PersistenceStatus>> observed;
  return observed;
}

void record_rejection(const std::string& label, PersistenceStatus status) {
  ledger().emplace_back(label, status);
}

void check_status(PersistenceStatus actual, PersistenceStatus expected, const std::string& label,
                  const char* file, int line) {
  pd_test::check(actual == expected,
                 label + ": observed " + std::string(to_string(actual)) + ", expected " +
                     std::string(to_string(expected)),
                 file, line);
}

void append_varint(std::vector<std::uint8_t>& out, std::uint64_t value) {
  std::uint64_t remaining = value;
  do {
    std::uint8_t byte = static_cast<std::uint8_t>(remaining & 0x7fU);
    remaining >>= 7;
    if (remaining != 0) {
      byte = static_cast<std::uint8_t>(byte | 0x80U);
    }
    out.push_back(byte);
  } while (remaining != 0);
}

std::vector<std::uint8_t> with_trailer(const std::vector<std::uint8_t>& payload) {
  std::vector<std::uint8_t> out = payload;
  const std::uint64_t trailer = fnv1a64(payload.data(), payload.size());
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>((trailer >> (8 * i)) & 0xffULL));
  }
  return out;
}

// One section of the store: the declared record count and the raw records.
struct Section {
  std::uint64_t count = 0;
  std::vector<std::uint8_t> records;
};

// Builds a store byte-for-byte from caller-supplied sections, so a case can
// present content the public encoder would never produce.
std::vector<std::uint8_t> build_store(std::uint64_t epoch,
                                      const std::vector<Section>& sections) {
  std::vector<std::uint8_t> payload;
  for (std::size_t i = 0; i < sizeof(kStoreMagic); ++i) {
    payload.push_back(static_cast<std::uint8_t>(kStoreMagic[i]));
  }
  ByteWriter header;
  header.u32(kPersistenceFormatVersion);
  header.u64(epoch);
  payload.insert(payload.end(), header.data().begin(), header.data().end());
  for (const Section& section : sections) {
    append_varint(payload, section.count);
    payload.insert(payload.end(), section.records.begin(), section.records.end());
  }
  return with_trailer(payload);
}

std::vector<std::uint8_t> encode_record(const std::function<void(ByteWriter&)>& write) {
  ByteWriter writer;
  write(writer);
  return writer.data();
}

std::vector<std::uint8_t> encode_policy_record(const DiversityPolicy& policy) {
  ByteWriter writer;
  encode_policy(writer, policy);
  return writer.data();
}

std::vector<std::uint8_t> encode_proof_record(const DiversityProof& proof) {
  ByteWriter writer;
  encode_proof(writer, proof);
  return writer.data();
}

std::vector<std::uint8_t> encode_snapshot_record(const ProofSnapshot& snapshot) {
  ByteWriter writer;
  encode_snapshot(writer, snapshot);
  return writer.data();
}

std::vector<std::uint8_t> store_with_records(const std::vector<std::uint8_t>& policies,
                                             std::uint64_t policy_count,
                                             const std::vector<std::uint8_t>& proofs,
                                             std::uint64_t proof_count) {
  return build_store(1, {{policy_count, policies},
                         {proof_count, proofs},
                         {0, {}},
                         {0, {}},
                         {0, {}},
                         {0, {}},
                         {0, {}}});
}

// A store the shipped encoder and decoder both accept, used as the base for
// targeted mutations.
struct ValidStore {
  StoreContents contents;
  std::vector<std::uint8_t> bytes;
  DiversityProof proof;
};

ValidStore make_valid_store(const Limits& limits) {
  Limits configured = limits;
  pd_test::Fixture fixture(configured);
  const DiversityPolicy policy =
      pd_test::make_policy("dpol-adversarial", {DiversityClass::LINK_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  const MutationResult published =
      fixture.runtime.publish_policy(policy, fixture.actor("adv-policy"));
  PD_CHECK_EQ(published.status, MutationStatus::APPLIED);
  fixture.evidence.set_path(
      pd_test::make_path("path-one", 1, {"node-one"}, {"link-one"}, {"dev-one"}, "ep-a", "ep-b"));
  fixture.evidence.set_path(
      pd_test::make_path("path-two", 1, {"node-two"}, {"link-two"}, {"dev-two"}, "ep-a", "ep-b"));
  ProofRequest request;
  request.policy = published.policy.id;
  request.policy_generation = published.policy.generation;
  request.paths.push_back(
      PathRef{PathId::parse("path-one"), PathAuthorityGeneration::from_value(1)});
  request.paths.push_back(
      PathRef{PathId::parse("path-two"), PathAuthorityGeneration::from_value(1)});
  const MutationResult committed = fixture.runtime.evaluate(request, fixture.actor("adv-eval"));
  PD_CHECK_EQ(committed.status, MutationStatus::APPLIED);

  ValidStore out;
  out.proof = committed.proof;
  out.contents.epoch = fixture.publication.current_epoch();
  out.contents.policies.push_back(*fixture.runtime.policy(request.policy));
  out.contents.proofs.push_back(committed.proof);
  out.bytes = encode_store(out.contents, configured);
  StoreContents round;
  std::string detail;
  PD_CHECK_EQ(decode_store(out.bytes.data(), out.bytes.size(), configured, round, detail),
              PersistenceStatus::OK);
  return out;
}

// Decodes into a sentinel that a caller could recognise, so "the decoder never
// handed back a usable store" is observable rather than assumed.
StoreContents sentinel_contents() {
  StoreContents sentinel;
  sentinel.epoch = CoordinatorEpoch::from_value(4242);
  sentinel.policies.push_back(pd_test::make_policy("dpol-sentinel", {DiversityClass::SITE_DISJOINT},
                                                   EndpointExemption::ANY_ENDPOINT, 2));
  return sentinel;
}

PersistenceStatus expect_rejection(const std::vector<std::uint8_t>& bytes,
                                   PersistenceStatus expected, bool untouched,
                                   const Limits& limits, const std::string& label) {
  const StoreContents sentinel = sentinel_contents();
  StoreContents out = sentinel;
  std::string detail;
  const PersistenceStatus status = decode_store(bytes.data(), bytes.size(), limits, out, detail);
  record_rejection(label, status);
  check_status(status, expected, label, __FILE__, __LINE__);
  PD_CHECK(!detail.empty());
  if (untouched) {
    PD_CHECK(out == sentinel);
  }
  return status;
}

void replace_first(std::vector<std::uint8_t>& bytes, const std::string& needle,
                   std::uint8_t value) {
  for (std::size_t i = 0; i + needle.size() <= bytes.size(); ++i) {
    bool match = true;
    for (std::size_t j = 0; j < needle.size(); ++j) {
      if (bytes[i + j] != static_cast<std::uint8_t>(needle[j])) {
        match = false;
        break;
      }
    }
    if (match) {
      bytes[i] = value;
      return;
    }
  }
}

}  // namespace

PD_TEST(empty_and_short_inputs_are_refused) {
  const Limits limits;
  std::string detail;
  StoreContents out;
  const PersistenceStatus null_status = decode_store(nullptr, 0, limits, out, detail);
  record_rejection("null", null_status);
  check_status(null_status, PersistenceStatus::EMPTY_FILE, "null", __FILE__, __LINE__);

  const std::vector<std::uint8_t> empty;
  const PersistenceStatus empty_status = decode_store(empty.data(), empty.size(), limits, out, detail);
  record_rejection("empty", empty_status);
  check_status(empty_status, PersistenceStatus::EMPTY_FILE, "empty", __FILE__, __LINE__);

  // Every length below the fixed header and trailer is truncated, not empty and
  // never a defaulted store.
  for (std::size_t size = 1; size < 28; ++size) {
    std::vector<std::uint8_t> short_buffer(size, 0x41U);
    const PersistenceStatus status =
        decode_store(short_buffer.data(), short_buffer.size(), limits, out, detail);
    record_rejection("short-" + std::to_string(size), status);
    check_status(status, PersistenceStatus::TRUNCATED, "short-" + std::to_string(size), __FILE__,
                 __LINE__);
  }
}

PD_TEST(magic_and_version_are_refused_before_any_record) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);

  std::vector<std::uint8_t> wrong_magic = store.bytes;
  wrong_magic[0] = static_cast<std::uint8_t>('X');
  expect_rejection(wrong_magic, PersistenceStatus::MALFORMED_MAGIC, true, limits, "wrong-magic");

  std::vector<std::uint8_t> short_magic = store.bytes;
  short_magic[7] = 0;
  expect_rejection(short_magic, PersistenceStatus::MALFORMED_MAGIC, true, limits,
                   "wrong-magic-tail");

  // The version is covered by the integrity trailer, so a real version change
  // is presented with a recomputed trailer and reaches the version check.
  for (std::uint32_t version : {0U, 2U, 0xffffffffU}) {
    std::vector<std::uint8_t> payload(store.bytes.begin(), store.bytes.end() - 8);
    payload[8] = static_cast<std::uint8_t>(version & 0xffU);
    payload[9] = static_cast<std::uint8_t>((version >> 8) & 0xffU);
    payload[10] = static_cast<std::uint8_t>((version >> 16) & 0xffU);
    payload[11] = static_cast<std::uint8_t>((version >> 24) & 0xffU);
    expect_rejection(with_trailer(payload), PersistenceStatus::UNSUPPORTED_VERSION, false, limits,
                     "version-" + std::to_string(version));
  }
}

PD_TEST(truncation_at_every_length_is_refused) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);
  const std::vector<std::uint8_t> payload(store.bytes.begin(), store.bytes.end() - 8);
  StoreContents out;
  std::string detail;
  for (std::size_t length = 1; length < payload.size(); ++length) {
    const std::vector<std::uint8_t> truncated =
        with_trailer(std::vector<std::uint8_t>(payload.begin(), payload.begin() + length));
    const PersistenceStatus status =
        decode_store(truncated.data(), truncated.size(), limits, out, detail);
    // A prefix that carries a valid trailer still ends before the last section:
    // the decoder reports the exhaustion rather than defaulting the missing
    // records away.
    check_status(status, PersistenceStatus::TRUNCATED, "truncated-" + std::to_string(length),
                 __FILE__, __LINE__);
  }
  record_rejection("truncation-sweep", PersistenceStatus::TRUNCATED);
}

PD_TEST(every_single_bit_flip_anywhere_in_the_file_is_refused) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);
  PD_REQUIRE(store.bytes.size() > 40);
  std::size_t checked = 0;
  for (std::size_t offset = 0; offset < store.bytes.size(); ++offset) {
    for (int bit = 0; bit < 8; ++bit) {
      std::vector<std::uint8_t> flipped = store.bytes;
      flipped[offset] = static_cast<std::uint8_t>(flipped[offset] ^ (1U << bit));
      StoreContents out;
      std::string detail;
      const PersistenceStatus status =
          decode_store(flipped.data(), flipped.size(), limits, out, detail);
      // A flipped magic byte is reported as such; every other flip in the fixed
      // header, the records or the trailer is caught by the integrity value.
      const PersistenceStatus expected = offset < 8 ? PersistenceStatus::MALFORMED_MAGIC
                                                    : PersistenceStatus::INTEGRITY_FAILURE;
      check_status(status, expected,
                   "flip-" + std::to_string(offset) + "-" + std::to_string(bit), __FILE__, __LINE__);
      ++checked;
    }
  }
  PD_CHECK(checked == store.bytes.size() * 8);
  record_rejection("bit-flip-sweep", PersistenceStatus::INTEGRITY_FAILURE);
}

PD_TEST(trailing_bytes_are_refused) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);
  std::vector<std::uint8_t> payload(store.bytes.begin(), store.bytes.end() - 8);
  payload.push_back(0x00U);
  expect_rejection(with_trailer(payload), PersistenceStatus::TRAILING_BYTES, false, limits,
                   "trailing-one-byte");

  std::vector<std::uint8_t> longer(store.bytes.begin(), store.bytes.end() - 8);
  for (int i = 0; i < 9; ++i) {
    longer.push_back(0xffU);
  }
  expect_rejection(with_trailer(longer), PersistenceStatus::TRAILING_BYTES, false, limits,
                   "trailing-nine-bytes");

  // The per-record codec does not own the end-of-record decision: the extra
  // byte stays visible to the caller, and the store loader is what refuses it.
  ByteWriter writer;
  encode_policy(writer, store.contents.policies.front());
  std::vector<std::uint8_t> record = writer.data();
  record.push_back(0x00U);
  ByteReader reader(record.data(), record.size());
  DiversityPolicy decoded;
  PD_CHECK_EQ(decode_policy(reader, limits, decoded), DecodeStatus::OK);
  PD_CHECK(!reader.at_end());
  PD_CHECK_EQ(reader.remaining(), std::size_t{1});
}

PD_TEST(duplicate_paths_where_forbidden_are_refused) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);
  DiversityProof proof = store.proof;
  PD_REQUIRE(proof.request.paths.size() == 2);
  proof.request.paths[1].path = proof.request.paths[0].path;
  proof.matrix.order[1] = proof.request.paths[0].path;
  const std::vector<std::uint8_t> record = encode_proof_record(proof);
  expect_rejection(store_with_records({}, 0, record, 1), PersistenceStatus::DUPLICATE_PATH, false,
                   limits, "duplicate-path");

  // The record codec reports the precise cause through the typed reason channel,
  // and the store surfaces that same status rather than a generic one.
  ByteReader reader(record.data(), record.size());
  DiversityProof decoded;
  DecodeFailure failure;
  PD_CHECK_EQ(decode_proof(reader, limits, decoded, &failure), DecodeStatus::INVALID_ENCODING);
  PD_CHECK(failure.classified());
  PD_CHECK(failure.status == PersistenceStatus::DUPLICATE_PATH);
  PD_CHECK_EQ(persistence_status_for(DecodeStatus::INVALID_ENCODING, failure),
              PersistenceStatus::DUPLICATE_PATH);
}

PD_TEST(matrix_and_conflict_references_are_validated) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);

  DiversityProof short_matrix = store.proof;
  PD_REQUIRE(short_matrix.matrix.cells.size() == 1);
  short_matrix.matrix.cells.clear();
  expect_rejection(store_with_records({}, 0, encode_proof_record(short_matrix), 1),
                   PersistenceStatus::MATRIX_DIMENSION_MISMATCH, false, limits,
                   "matrix-dimensions");

  DiversityProof wide_matrix = store.proof;
  wide_matrix.matrix.cells.push_back(wide_matrix.matrix.cells.front());
  expect_rejection(store_with_records({}, 0, encode_proof_record(wide_matrix), 1),
                   PersistenceStatus::MATRIX_DIMENSION_MISMATCH, false, limits,
                   "matrix-extra-cell");

  DiversityProof unknown_conflict = store.proof;
  SharedResource conflict;
  conflict.kind = ConflictClass::SHARED_LINK;
  conflict.relation = DomainRelation::FAILURE_DOMAIN;
  conflict.id = "link-one";
  conflict.paths = {0, 7};
  unknown_conflict.conflicts.push_back(conflict);
  unknown_conflict.conflicts_total = 1;
  expect_rejection(store_with_records({}, 0, encode_proof_record(unknown_conflict), 1),
                   PersistenceStatus::UNKNOWN_REFERENCE, false, limits,
                   "conflict-unknown-index");

  DiversityProof unknown_class_conflict = store.proof;
  unknown_class_conflict.classes.front().shared.push_back(conflict);
  unknown_class_conflict.classes.front().shared_total = 1;
  expect_rejection(store_with_records({}, 0, encode_proof_record(unknown_class_conflict), 1),
                   PersistenceStatus::UNKNOWN_REFERENCE, false, limits,
                   "class-conflict-unknown-index");
}

PD_TEST(proven_claims_with_incomplete_evidence_are_refused) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);
  PD_REQUIRE(store.proof.outcome == ProofOutcome::PROVEN_DIVERSE);
  PD_REQUIRE(!store.proof.classes.empty());

  DiversityProof incomplete_class = store.proof;
  incomplete_class.classes.front().evidence_complete = false;
  expect_rejection(store_with_records({}, 0, encode_proof_record(incomplete_class), 1),
                   PersistenceStatus::INCOMPLETE_EVIDENCE_CLAIM, false, limits,
                   "proven-incomplete-class");

  // A proven claim that also carries a conflict contradicts itself.
  DiversityProof proven_with_conflict = store.proof;
  SharedResource conflict;
  conflict.kind = ConflictClass::SHARED_LINK;
  conflict.relation = DomainRelation::FAILURE_DOMAIN;
  conflict.id = "link-one";
  conflict.paths = {0, 1};
  proven_with_conflict.conflicts.push_back(conflict);
  proven_with_conflict.conflicts_total = 1;
  expect_rejection(store_with_records({}, 0, encode_proof_record(proven_with_conflict), 1),
                   PersistenceStatus::INCOMPLETE_EVIDENCE_CLAIM, false, limits,
                   "proven-with-conflict");

  // A conflict list that claims fewer total conflicts than it carries is
  // arithmetically impossible.
  DiversityProof understated = store.proof;
  understated.outcome = ProofOutcome::NOT_DIVERSE;
  understated.currentness = Currentness::REVALIDATION_REQUIRED;
  understated.classes.front().outcome = ProofOutcome::NOT_DIVERSE;
  understated.classes.front().shared.push_back(conflict);
  understated.classes.front().shared_total = 1;
  understated.conflicts.push_back(conflict);
  understated.conflicts_total = 0;
  // No public status names an internally contradictory total, so this one stays
  // conservatively unclassified rather than being over-claimed.
  expect_rejection(store_with_records({}, 0, encode_proof_record(understated), 1),
                   PersistenceStatus::INTERNAL_INCONSISTENCY, false, limits,
                   "conflicts-total-understated");
}

PD_TEST(invalid_witness_subsets_are_refused) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);

  // A named subset smaller than the proven achievement contradicts itself. A
  // named subset larger than the achievement is legal: it is the optimistic
  // witness an unresolved evaluation reports.
  DiversityProof count_mismatch = store.proof;
  count_mismatch.witness.present = true;
  count_mismatch.witness.requested_k = 3;
  count_mismatch.witness.achieved = 3;
  count_mismatch.witness.indices = {0, 1};
  expect_rejection(store_with_records({}, 0, encode_proof_record(count_mismatch), 1),
                   PersistenceStatus::INVALID_WITNESS, false, limits, "witness-count");

  DiversityProof optimistic = store.proof;
  optimistic.witness.present = true;
  optimistic.witness.requested_k = 2;
  optimistic.witness.achieved = 1;
  optimistic.witness.indices = {0, 1};
  const std::vector<std::uint8_t> optimistic_record = encode_proof_record(optimistic);
  const std::vector<std::uint8_t> optimistic_store =
      store_with_records({}, 0, optimistic_record, 1);
  StoreContents optimistic_contents;
  std::string optimistic_detail;
  PD_CHECK_EQ(
      decode_store(optimistic_store.data(), optimistic_store.size(), limits, optimistic_contents,
                   optimistic_detail),
      PersistenceStatus::OK);
  PD_REQUIRE(optimistic_contents.proofs.size() == 1);
  PD_CHECK(optimistic_contents.proofs.front().witness.indices.size() >
            static_cast<std::size_t>(optimistic_contents.proofs.front().witness.achieved));

  DiversityProof unsorted = store.proof;
  unsorted.witness.present = true;
  unsorted.witness.requested_k = 2;
  unsorted.witness.achieved = 2;
  unsorted.witness.indices = {1, 0};
  expect_rejection(store_with_records({}, 0, encode_proof_record(unsorted), 1),
                   PersistenceStatus::INVALID_WITNESS, false, limits, "witness-order");

  DiversityProof repeated = store.proof;
  repeated.witness.present = true;
  repeated.witness.requested_k = 2;
  repeated.witness.achieved = 2;
  repeated.witness.indices = {0, 0};
  expect_rejection(store_with_records({}, 0, encode_proof_record(repeated), 1),
                   PersistenceStatus::INVALID_WITNESS, false, limits, "witness-repeat");

  DiversityProof out_of_range = store.proof;
  out_of_range.witness.present = true;
  out_of_range.witness.requested_k = 2;
  out_of_range.witness.achieved = 2;
  out_of_range.witness.indices = {0, 9};
  expect_rejection(store_with_records({}, 0, encode_proof_record(out_of_range), 1),
                   PersistenceStatus::INVALID_WITNESS, false, limits, "witness-range");
}

PD_TEST(invalid_policy_encodings_are_refused) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);
  PD_REQUIRE(!store.contents.policies.empty());

  DiversityPolicy unknown_class = store.contents.policies.front();
  unknown_class.required_classes.front() = static_cast<DiversityClass>(99);
  expect_rejection(store_with_records(encode_policy_record(unknown_class), 1, {}, 0),
                   PersistenceStatus::INVALID_ENUM, false, limits, "policy-class");

  DiversityPolicy unknown_exemption = store.contents.policies.front();
  unknown_exemption.endpoint_exemption = static_cast<EndpointExemption>(77);
  expect_rejection(store_with_records(encode_policy_record(unknown_exemption), 1, {}, 0),
                   PersistenceStatus::INVALID_ENUM, false, limits, "policy-exemption");

  DiversityPolicy unset_generation = store.contents.policies.front();
  unset_generation.generation = DiversityPolicyGeneration();
  expect_rejection(store_with_records(encode_policy_record(unset_generation), 1, {}, 0),
                   PersistenceStatus::IMPOSSIBLE_GENERATION, false, limits, "policy-generation");

  // The record codec names the exact cause for each of them.
  for (const DiversityPolicy& policy :
       {unknown_class, unknown_exemption, unset_generation}) {
    const std::vector<std::uint8_t> record = encode_policy_record(policy);
    ByteReader reader(record.data(), record.size());
    DiversityPolicy decoded;
    PD_CHECK_EQ(decode_policy(reader, limits, decoded), DecodeStatus::INVALID_ENCODING);
  }

  // A domain-backed class with no declared relation set is a policy defect.
  DiversityPolicy missing_relations = store.contents.policies.front();
  missing_relations.required_classes = {DiversityClass::FAILURE_DOMAIN_DISJOINT};
  missing_relations.allowed_failure_domain_relations.clear();
  expect_rejection(store_with_records(encode_policy_record(missing_relations), 1, {}, 0),
                   PersistenceStatus::INVALID_ENUM, false, limits, "policy-relations");
}

PD_TEST(impossible_generations_are_refused) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);
  PD_REQUIRE(store.proof.lifecycle == LifecycleState::CURRENT);

  const auto mutate = [&](int field) {
    DiversityProof proof = store.proof;
    switch (field) {
      case 0:
        proof.dependencies.policy_generation = DiversityPolicyGeneration::from_value(0);
        break;
      case 1:
        proof.dependencies.topology_generation = TopologyGeneration::from_value(0);
        break;
      case 2:
        proof.dependencies.failure_domain_generation = FailureDomainGeneration::from_value(0);
        break;
      default:
        proof.dependencies.epoch = CoordinatorEpoch::from_value(0);
        break;
    }
    return proof;
  };
  for (int field = 0; field < 4; ++field) {
    expect_rejection(store_with_records({}, 0, encode_proof_record(mutate(field)), 1),
                     PersistenceStatus::IMPOSSIBLE_GENERATION, false, limits,
                     "zero-generation-" + std::to_string(field));
  }

  // The same proof with a zero generation but a non-current lifecycle is a
  // historical revision, which is legal: the rule is about live claims only.
  DiversityProof historical = mutate(0);
  historical.lifecycle = LifecycleState::HISTORICAL;
  historical.currentness = Currentness::REVALIDATION_REQUIRED;
  const std::vector<std::uint8_t> record = encode_proof_record(historical);
  const std::vector<std::uint8_t> bytes = store_with_records({}, 0, record, 1);
  StoreContents contents;
  std::string detail;
  const PersistenceStatus status =
      decode_store(bytes.data(), bytes.size(), limits, contents, detail);
  PD_CHECK_EQ(status, PersistenceStatus::OK);
  PD_REQUIRE(contents.proofs.size() == 1);
  PD_CHECK_EQ(contents.proofs.front().lifecycle, LifecycleState::HISTORICAL);
}

PD_TEST(malformed_identities_are_refused_with_their_own_status) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);
  const std::string boot = mint_worker_boot_id().str();

  // A session record with an empty publisher identity.
  std::vector<std::uint8_t> session = encode_record([&](ByteWriter& writer) {
    writer.text(std::string_view());
    writer.text(boot);
    writer.u64(1);
    writer.text(default_scope().view());
    writer.boolean(false);
  });
  expect_rejection(build_store(1, {{0, {}}, {0, {}}, {1, session}, {0, {}}, {0, {}}, {0, {}}, {0, {}}}),
                   PersistenceStatus::MALFORMED_IDENTITY, false, limits, "session-identity");

  // A session record whose identity text is not in the identity alphabet.
  session = encode_record([&](ByteWriter& writer) {
    writer.text("pub bad");
    writer.text(boot);
    writer.u64(1);
    writer.text(default_scope().view());
    writer.boolean(false);
  });
  expect_rejection(build_store(1, {{0, {}}, {0, {}}, {1, session}, {0, {}}, {0, {}}, {0, {}}, {0, {}}}),
                   PersistenceStatus::MALFORMED_IDENTITY, false, limits, "session-alphabet");

  // A fenced-boot record with an empty boot identity.
  const std::vector<std::uint8_t> fenced = encode_record(
      [&](ByteWriter& writer) { writer.text(std::string_view()); });
  expect_rejection(build_store(1, {{0, {}}, {0, {}}, {0, {}}, {1, fenced}, {0, {}}, {0, {}}, {0, {}}}),
                   PersistenceStatus::MALFORMED_IDENTITY, false, limits, "fenced-identity");

  // An attempt record whose proof identity is malformed.
  const std::vector<std::uint8_t> attempt = encode_record([&](ByteWriter& writer) {
    writer.text(mint_mutation_attempt_id().view());
    const Digest payload = Digest::of("payload", 7);
    writer.bytes(payload.bytes().data(), payload.bytes().size());
    writer.text("not a proof id");
  });
  expect_rejection(build_store(1, {{0, {}}, {0, {}}, {0, {}}, {0, {}}, {1, attempt}, {0, {}}, {0, {}}}),
                   PersistenceStatus::MALFORMED_IDENTITY, false, limits, "attempt-identity");

  // A history record whose proof identity is malformed.
  const std::vector<std::uint8_t> history = encode_record([&](ByteWriter& writer) {
    writer.text("bad identity");
    writer.varint(0);
  });
  expect_rejection(build_store(1, {{0, {}}, {0, {}}, {0, {}}, {0, {}}, {0, {}}, {1, history}, {0, {}}}),
                   PersistenceStatus::MALFORMED_IDENTITY, false, limits, "history-identity");

  // A malformed PathId inside the proof request.
  std::vector<std::uint8_t> proof_record = encode_proof_record(store.proof);
  replace_first(proof_record, "path-one", static_cast<std::uint8_t>(' '));
  expect_rejection(store_with_records({}, 0, proof_record, 1),
                   PersistenceStatus::MALFORMED_IDENTITY, false, limits, "path-identity");
}

// The mapping itself is a product surface, so it is pinned directly: a future
// refactor that collapses a recognised corruption back into the generic status
// fails here rather than silently degrading an operator's diagnosis.
PD_TEST(decode_failure_maps_to_a_specific_status) {
  const DecodeFailure unset;
  PD_CHECK(!unset.classified());
  PD_CHECK_EQ(persistence_status_for(DecodeStatus::INVALID_ENCODING, unset),
              PersistenceStatus::INTERNAL_INCONSISTENCY);

  // The non-record statuses keep their own meaning whatever the classification.
  PD_CHECK_EQ(persistence_status_for(DecodeStatus::OK, unset), PersistenceStatus::OK);
  PD_CHECK_EQ(persistence_status_for(DecodeStatus::TRUNCATED, unset), PersistenceStatus::TRUNCATED);
  PD_CHECK_EQ(persistence_status_for(DecodeStatus::LENGTH_OVERRUN, unset),
              PersistenceStatus::TRUNCATED);
  PD_CHECK_EQ(persistence_status_for(DecodeStatus::TRAILING_BYTES, unset),
              PersistenceStatus::TRAILING_BYTES);
  PD_CHECK_EQ(persistence_status_for(DecodeStatus::LIMIT_EXCEEDED, unset),
              PersistenceStatus::LIMIT_EXCEEDED);

  // Every declared corruption class survives the mapping unchanged.
  const PersistenceStatus specific[] = {
      PersistenceStatus::DUPLICATE_PATH,
      PersistenceStatus::INVALID_ENUM,
      PersistenceStatus::IMPOSSIBLE_GENERATION,
      PersistenceStatus::MATRIX_DIMENSION_MISMATCH,
      PersistenceStatus::UNKNOWN_REFERENCE,
      PersistenceStatus::INCOMPLETE_EVIDENCE_CLAIM,
      PersistenceStatus::INVALID_WITNESS,
      PersistenceStatus::ARITHMETIC_OVERFLOW,
      PersistenceStatus::MALFORMED_IDENTITY,
      PersistenceStatus::INTERNAL_INCONSISTENCY};
  for (PersistenceStatus expected : specific) {
    DecodeFailure failure;
    failure.classify(expected);
    PD_CHECK(failure.classified());
    PD_CHECK_EQ(failure.status, expected);
    PD_CHECK_EQ(persistence_status_for(DecodeStatus::INVALID_ENCODING, failure), expected);
    PD_CHECK(is_defined_persistence_status(static_cast<std::uint8_t>(expected)));
  }

  // A classified failure is sticky through the public decoder as well.
  const Limits limits;
  const ValidStore store = make_valid_store(limits);
  DiversityProof duplicated = store.proof;
  PD_REQUIRE(duplicated.request.paths.size() == 2);
  duplicated.request.paths[1].path = duplicated.request.paths[0].path;
  duplicated.matrix.order[1] = duplicated.request.paths[0].path;
  const std::vector<std::uint8_t> record = encode_proof_record(duplicated);
  ByteReader reader(record.data(), record.size());
  DiversityProof decoded;
  DecodeFailure failure;
  PD_CHECK_EQ(decode_proof(reader, limits, decoded, &failure), DecodeStatus::INVALID_ENCODING);
  PD_CHECK(failure.status == PersistenceStatus::DUPLICATE_PATH);
  PD_CHECK_EQ(persistence_status_for(reader.status(), failure), PersistenceStatus::DUPLICATE_PATH);
}

// A varint that is a well-formed number but cannot be represented in the 32-bit
// field it encodes is an arithmetic overflow, not a malformed encoding.
PD_TEST(arithmetic_overflow_in_a_record_is_named) {
  const Limits limits;
  const std::vector<std::uint8_t> overflow_policy = encode_record([&](ByteWriter& writer) {
    writer.text("dpol-overflow");
    writer.u64(1);
    writer.text("scope-default");
    writer.varint(1);
    writer.u8(static_cast<std::uint8_t>(DiversityClass::LINK_DISJOINT));
    writer.u8(static_cast<std::uint8_t>(EndpointExemption::SHARED_SOURCE_AND_DESTINATION));
    // 2^32 does not fit the 32-bit minimum-independent-path count.
    writer.varint(4294967296ULL);
  });
  expect_rejection(build_store(1, {{1, overflow_policy}, {0, {}}, {0, {}}, {0, {}}, {0, {}}, {0, {}}, {0, {}}}),
                   PersistenceStatus::ARITHMETIC_OVERFLOW, false, limits,
                   "policy-minimum-overflow");

  // The same value reaching the public codec carries the same reason.
  ByteReader reader(overflow_policy.data(), overflow_policy.size());
  DiversityPolicy decoded;
  DecodeFailure failure;
  PD_CHECK_EQ(decode_policy(reader, limits, decoded, &failure), DecodeStatus::INVALID_ENCODING);
  PD_CHECK(failure.status == PersistenceStatus::ARITHMETIC_OVERFLOW);
  PD_CHECK_EQ(persistence_status_for(reader.status(), failure),
              PersistenceStatus::ARITHMETIC_OVERFLOW);
}

PD_TEST(absurd_counts_and_store_limits_are_refused) {
  const ValidStore store = make_valid_store(Limits());
  const Limits limits;

  // A declared count that cannot fit the bytes present.
  std::vector<std::uint8_t> payload(store.bytes.begin(), store.bytes.end() - 8);
  std::vector<std::uint8_t> absurd;
  absurd.insert(absurd.end(), payload.begin(), payload.begin() + 20);
  append_varint(absurd, static_cast<std::uint64_t>(limits.max_store_records));
  for (int section = 0; section < 6; ++section) {
    append_varint(absurd, 0);
  }
  expect_rejection(with_trailer(absurd), PersistenceStatus::ABSURD_COUNT, false, limits,
                   "absurd-count");

  // A declared count above the record budget.
  std::vector<std::uint8_t> over;
  over.insert(over.end(), payload.begin(), payload.begin() + 20);
  append_varint(over, static_cast<std::uint64_t>(limits.max_store_records) + 1);
  for (int section = 0; section < 6; ++section) {
    append_varint(over, 0);
  }
  expect_rejection(with_trailer(over), PersistenceStatus::RECORD_LIMIT_EXCEEDED, false, limits,
                   "record-limit");

  // A store larger than the byte budget is refused before it is parsed.
  Limits small_bytes = limits;
  small_bytes.max_store_bytes = store.bytes.size() - 1;
  PD_REQUIRE(small_bytes.self_consistent());
  expect_rejection(store.bytes, PersistenceStatus::SIZE_LIMIT_EXCEEDED, true, small_bytes,
                   "size-limit");

  // A store whose first section declares more records than the per-store
  // budget. Zero is not a legal budget at all, which the limit set refuses to
  // express.
  Limits few_records = limits;
  few_records.max_store_records = 0;
  PD_CHECK(!few_records.self_consistent());
  Limits one_record = limits;
  one_record.max_store_records = 1;
  PD_REQUIRE(one_record.self_consistent());
  PD_REQUIRE(store.contents.policies.size() == 1);
  std::vector<std::uint8_t> two_policies = encode_policy_record(store.contents.policies.front());
  const std::vector<std::uint8_t> also = encode_policy_record(store.contents.policies.front());
  two_policies.insert(two_policies.end(), also.begin(), also.end());
  expect_rejection(store_with_records(two_policies, 2, {}, 0),
                   PersistenceStatus::RECORD_LIMIT_EXCEEDED, false, one_record, "record-budget");

  // A history record that declares more revisions than the history budget.
  const std::uint64_t over_history =
      static_cast<std::uint64_t>(limits.max_history) + 1ULL;
  const std::vector<std::uint8_t> history = encode_record([&](ByteWriter& writer) {
    writer.text(store.proof.id.view());
    writer.varint(over_history);
  });
  expect_rejection(build_store(1, {{0, {}}, {0, {}}, {0, {}}, {0, {}}, {0, {}}, {1, history}, {0, {}}}),
                   PersistenceStatus::RECORD_LIMIT_EXCEEDED, false, limits, "history-budget");
}

PD_TEST(a_rejected_decode_never_yields_a_usable_store) {
  const Limits limits;
  const ValidStore store = make_valid_store(limits);

  // A sentinel the caller could act on is never left holding decoded content
  // when the decode was refused before any record was admitted.
  std::vector<std::uint8_t> corrupt = store.bytes;
  corrupt[16] = static_cast<std::uint8_t>(corrupt[16] ^ 0x01U);
  expect_rejection(corrupt, PersistenceStatus::INTEGRITY_FAILURE, true, limits, "sentinel-integrity");

  // A runtime that refuses a load keeps exactly the state it had.
  pd_test::Fixture fixture;
  const DiversityPolicy policy =
      pd_test::make_policy("dpol-recovery-adversarial", {DiversityClass::LINK_DISJOINT},
                           EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  PD_CHECK_EQ(fixture.runtime.publish_policy(policy, fixture.actor("adv-live")).status,
              MutationStatus::APPLIED);
  const std::string before = fixture.runtime.render();
  const RuntimeStats stats_before = fixture.runtime.stats();

  const StoreContents sentinel = sentinel_contents();
  StoreContents out = sentinel;
  std::string detail;
  const PersistenceStatus status =
      decode_store(corrupt.data(), corrupt.size(), limits, out, detail);
  record_rejection("runtime-refusal", status);
  PD_CHECK_EQ(status, PersistenceStatus::INTEGRITY_FAILURE);
  PD_CHECK(out == sentinel);

  // The refused store is a store whose first bytes are not the store magic: a
  // caller that ignored the status would be reading its own previous value.
  PD_REQUIRE(!out.policies.empty());
  PD_CHECK(!(out.policies.front() == store.contents.policies.front()));
  PD_CHECK_EQ(fixture.runtime.render(), before);
  PD_CHECK(fixture.runtime.stats() == stats_before);
}

PD_TEST(the_rejection_taxonomy_is_distinct) {
  const PersistenceStatus required[] = {
      PersistenceStatus::EMPTY_FILE,          PersistenceStatus::MALFORMED_MAGIC,
      PersistenceStatus::UNSUPPORTED_VERSION, PersistenceStatus::TRUNCATED,
      PersistenceStatus::INTEGRITY_FAILURE,   PersistenceStatus::TRAILING_BYTES,
      PersistenceStatus::RECORD_LIMIT_EXCEEDED, PersistenceStatus::SIZE_LIMIT_EXCEEDED,
      PersistenceStatus::MALFORMED_IDENTITY, PersistenceStatus::ABSURD_COUNT,
      PersistenceStatus::DUPLICATE_PATH, PersistenceStatus::INVALID_ENUM,
      PersistenceStatus::IMPOSSIBLE_GENERATION, PersistenceStatus::MATRIX_DIMENSION_MISMATCH,
      PersistenceStatus::UNKNOWN_REFERENCE, PersistenceStatus::INCOMPLETE_EVIDENCE_CLAIM,
      PersistenceStatus::INVALID_WITNESS, PersistenceStatus::ARITHMETIC_OVERFLOW,
      PersistenceStatus::INTERNAL_INCONSISTENCY};
  PD_CHECK(ledger().size() >= 20);
  for (const auto& entry : ledger()) {
    PD_CHECK(!entry.first.empty());
    PD_CHECK(entry.second != PersistenceStatus::OK);
  }
  for (PersistenceStatus expected : required) {
    bool observed = false;
    for (const auto& entry : ledger()) {
      if (entry.second == expected) {
        observed = true;
      }
    }
    pd_test::check(observed, std::string("no case produced ") + std::string(to_string(expected)),
                   __FILE__, __LINE__);
  }
  for (const auto& entry : ledger()) {
    PD_CHECK(is_defined_persistence_status(static_cast<std::uint8_t>(entry.second)));
    PD_CHECK(to_string(entry.second) != "UNKNOWN");
  }
}

PD_TEST_MAIN()
