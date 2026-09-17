// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Durable-store coverage. Every assertion runs against the shipped codec and
// the shipped runtime: the suite never re-implements the encoding it checks.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

constexpr char kStoreMagic[8] = {'P', 'D', 'F', 'S', 'T', 'O', 'R', 'E'};

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

// Appends the integrity trailer the decoder recomputes over the payload.
std::vector<std::uint8_t> with_trailer(const std::vector<std::uint8_t>& payload) {
  std::vector<std::uint8_t> out = payload;
  const std::uint64_t trailer = fnv1a64(payload.data(), payload.size());
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>((trailer >> (8 * i)) & 0xffULL));
  }
  return out;
}

// Store header plus seven empty sections: the smallest legal store, used as the
// base for the hand-crafted count and truncation cases.
std::vector<std::uint8_t> empty_store_bytes() {
  std::vector<std::uint8_t> payload;
  for (std::size_t i = 0; i < sizeof(kStoreMagic); ++i) {
    payload.push_back(static_cast<std::uint8_t>(kStoreMagic[i]));
  }
  ByteWriter writer;
  writer.u32(kPersistenceFormatVersion);
  writer.u64(1);
  payload.insert(payload.end(), writer.data().begin(), writer.data().end());
  for (int section = 0; section < 7; ++section) {
    append_varint(payload, 0);
  }
  return with_trailer(payload);
}

bool write_file(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream.is_open()) {
    return false;
  }
  if (!bytes.empty()) {
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
  }
  stream.flush();
  return stream.good();
}

std::vector<std::uint8_t> read_file(const std::string& path) {
  std::vector<std::uint8_t> out;
  std::ifstream stream(path, std::ios::binary);
  if (!stream.is_open()) {
    return out;
  }
  char byte = 0;
  while (stream.get(byte)) {
    out.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(byte)));
  }
  return out;
}

std::size_t count_temporary_siblings(const std::filesystem::path& target) {
  std::size_t count = 0;
  std::error_code error;
  for (const std::filesystem::directory_entry& entry :
       std::filesystem::directory_iterator(target.parent_path(), error)) {
    const std::string name = entry.path().filename().string();
    if (name.rfind(target.filename().string() + ".tmp-", 0) == 0) {
      ++count;
    }
  }
  return count;
}

MutationResult publish_policy(pd_test::Fixture& fixture, const DiversityPolicy& policy,
                              const std::string& label) {
  return fixture.runtime.publish_policy(policy, fixture.actor(label));
}

MutationResult evaluate(pd_test::Fixture& fixture, const ProofRequest& request,
                        const std::string& label) {
  return fixture.runtime.evaluate(request, fixture.actor(label));
}

// Two links-disjoint paths published under one policy, plus the request that
// evaluates them.
struct DisjointPair {
  DiversityPolicyId policy;
  DiversityPolicyGeneration policy_generation;
  ProofRequest request;
  DiversityProofId proof;
};

void install_paths(pd_test::Fixture& fixture) {
  fixture.evidence.set_path(
      pd_test::make_path("path-a", 1, {"node-a"}, {"link-a"}, {"device-a"}, "ep-src", "ep-dst"));
  fixture.evidence.set_path(
      pd_test::make_path("path-b", 1, {"node-b"}, {"link-b"}, {"device-b"}, "ep-src", "ep-dst"));
}

DisjointPair install_pair(pd_test::Fixture& fixture, const std::string& policy_id,
                          const std::vector<DiversityClass>& classes, const std::string& label) {
  const DiversityPolicy policy = pd_test::make_policy(
      policy_id, classes, EndpointExemption::SHARED_SOURCE_AND_DESTINATION, 2);
  const MutationResult published = publish_policy(fixture, policy, label + "-policy");
  PD_CHECK_EQ(published.status, MutationStatus::APPLIED);

  install_paths(fixture);

  DisjointPair pair;
  pair.policy = published.policy.id;
  pair.policy_generation = published.policy.generation;
  pair.request.policy = pair.policy;
  pair.request.policy_generation = pair.policy_generation;
  pair.request.paths.push_back(
      PathRef{PathId::parse("path-a"), PathAuthorityGeneration::from_value(1)});
  pair.request.paths.push_back(
      PathRef{PathId::parse("path-b"), PathAuthorityGeneration::from_value(1)});
  pair.proof = proof_identity(pair.request);
  return pair;
}

// Makes path-b share link-a so the pair is evaluated as NOT_DIVERSE.
void make_pair_conflicting(pd_test::Fixture& fixture) {
  fixture.evidence.set_path(
      pd_test::make_path("path-b", 1, {"node-b"}, {"link-a"}, {"device-b"}, "ep-src", "ep-dst"));
}

void restore_pair_conflict_free(pd_test::Fixture& fixture) {
  fixture.evidence.set_path(
      pd_test::make_path("path-b", 1, {"node-b"}, {"link-b"}, {"device-b"}, "ep-src", "ep-dst"));
}

}  // namespace

PD_TEST(store_round_trip_preserves_policies_proofs_history_and_snapshots) {
  pd_test::Fixture fixture;
  const DisjointPair pair = install_pair(fixture, "dpol-round-trip",
                                         {DiversityClass::LINK_DISJOINT}, "rt");

  const MutationResult first = evaluate(fixture, pair.request, "rt-1");
  PD_CHECK_EQ(first.status, MutationStatus::APPLIED);
  PD_CHECK_EQ(first.proof.outcome, ProofOutcome::PROVEN_DIVERSE);
  PD_CHECK_EQ(first.proof.generation.value(), std::uint64_t{1});

  make_pair_conflicting(fixture);
  const MutationResult second = evaluate(fixture, pair.request, "rt-2");
  PD_CHECK_EQ(second.status, MutationStatus::APPLIED);
  PD_CHECK_EQ(second.proof.outcome, ProofOutcome::NOT_DIVERSE);
  PD_CHECK(!second.proof.conflicts.empty());

  restore_pair_conflict_free(fixture);
  const MutationResult third = evaluate(fixture, pair.request, "rt-3");
  PD_CHECK_EQ(third.status, MutationStatus::APPLIED);
  PD_CHECK_EQ(third.proof.outcome, ProofOutcome::PROVEN_DIVERSE);

  const std::vector<DiversityProof> history = fixture.runtime.history(pair.proof);
  PD_CHECK_EQ(history.size(), std::size_t{2});
  PD_CHECK_EQ(fixture.runtime.snapshot_ids(pair.proof).size(), std::size_t{3});
  const std::optional<ProofSnapshot> snapshot = fixture.runtime.snapshot(pair.proof);
  PD_REQUIRE(snapshot.has_value());

  const std::filesystem::path path = pd_test::unique_test_path("store-round-trip.pds");
  PD_CHECK_EQ(fixture.runtime.save(path.string()), PersistenceStatus::OK);
  const std::vector<std::uint8_t> bytes = read_file(path.string());
  PD_CHECK(!bytes.empty());

  StoreContents contents;
  std::string detail;
  const PersistenceStatus status =
      decode_store(bytes.data(), bytes.size(), fixture.limits, contents, detail);
  PD_CHECK_EQ(status, PersistenceStatus::OK);
  PD_CHECK(detail.empty());

  PD_CHECK_EQ(contents.policies.size(), fixture.runtime.policy_count());
  PD_CHECK_EQ(contents.proofs.size(), fixture.runtime.proof_count());
  PD_CHECK_EQ(contents.epoch, fixture.publication.current_epoch());
  PD_REQUIRE(contents.policies.size() == 1);
  PD_CHECK(contents.policies.front() == *fixture.runtime.policy(pair.policy));
  PD_REQUIRE(contents.proofs.size() == 1);
  PD_CHECK(contents.proofs.front() == *fixture.runtime.proof(pair.proof));
  PD_REQUIRE(contents.history.size() == 1);
  PD_CHECK_EQ(contents.history.front().first, pair.proof);
  PD_CHECK_EQ(contents.history.front().second.size(), history.size());
  PD_CHECK(contents.history.front().second == history);
  PD_REQUIRE(contents.snapshots.size() == 1);
  PD_CHECK(contents.snapshots.front() == *snapshot);

  // A store decoded once re-encodes to exactly the bytes it was decoded from,
  // and the second decode agrees with the first.
  const std::vector<std::uint8_t> reencoded = encode_store(contents, fixture.limits);
  PD_CHECK(reencoded == bytes);
  StoreContents again;
  std::string again_detail;
  PD_CHECK_EQ(decode_store(reencoded.data(), reencoded.size(), fixture.limits, again, again_detail),
              PersistenceStatus::OK);
  PD_CHECK(again == contents);
}

PD_TEST(individual_records_round_trip_through_their_own_codecs) {
  pd_test::Fixture fixture;
  const DisjointPair pair = install_pair(fixture, "dpol-records",
                                         {DiversityClass::LINK_DISJOINT,
                                          DiversityClass::TRANSIT_NODE_DISJOINT},
                                         "rec");
  const MutationResult result = evaluate(fixture, pair.request, "rec-1");
  PD_CHECK_EQ(result.status, MutationStatus::APPLIED);
  PD_REQUIRE(result.has_proof);
  const std::optional<DiversityPolicy> published = fixture.runtime.policy(pair.policy);
  PD_REQUIRE(published.has_value());

  {
    ByteWriter writer;
    encode_policy(writer, *published);
    ByteReader reader(writer.data().data(), writer.size());
    DiversityPolicy decoded;
    PD_CHECK_EQ(decode_policy(reader, fixture.limits, decoded), DecodeStatus::OK);
    PD_CHECK(reader.at_end());
    PD_CHECK(decoded == *published);
  }
  {
    ByteWriter writer;
    encode_proof(writer, result.proof);
    ByteReader reader(writer.data().data(), writer.size());
    DiversityProof decoded;
    PD_CHECK_EQ(decode_proof(reader, fixture.limits, decoded), DecodeStatus::OK);
    PD_CHECK(reader.at_end());
    PD_CHECK(decoded == result.proof);
    PD_CHECK(decoded.semantic_digest == result.proof.semantic_digest);
  }
  {
    const std::optional<ProofSnapshot> snapshot = fixture.runtime.snapshot(result.proof.id);
    PD_REQUIRE(snapshot.has_value());
    ByteWriter writer;
    encode_snapshot(writer, *snapshot);
    ByteReader reader(writer.data().data(), writer.size());
    ProofSnapshot decoded;
    PD_CHECK_EQ(decode_snapshot(reader, fixture.limits, decoded), DecodeStatus::OK);
    PD_CHECK(reader.at_end());
    PD_CHECK(decoded == *snapshot);
  }
}

PD_TEST(a_store_written_by_one_runtime_loads_into_a_fresh_runtime) {
  const std::filesystem::path source = pd_test::unique_test_path("hand-over.pds");
  const std::filesystem::path copy = pd_test::unique_test_path("hand-over-copy.pds");
  DiversityProofId proof;
  std::size_t history_size = 0;
  {
    pd_test::Fixture writer_fixture;
    const DisjointPair pair = install_pair(writer_fixture, "dpol-hand-over",
                                           {DiversityClass::LINK_DISJOINT}, "ho");
    PD_CHECK_EQ(evaluate(writer_fixture, pair.request, "ho-1").status, MutationStatus::APPLIED);
    make_pair_conflicting(writer_fixture);
    PD_CHECK_EQ(evaluate(writer_fixture, pair.request, "ho-2").status, MutationStatus::APPLIED);
    proof = pair.proof;
    history_size = writer_fixture.runtime.history(proof).size();
    PD_CHECK_EQ(writer_fixture.runtime.save(source.string()), PersistenceStatus::OK);
    PD_CHECK(writer_fixture.publication.fence_boot(mint_worker_boot_id()) ==
             AuthorityStatus::ACCEPTED);

    pd_test::Fixture reader_fixture;
    PD_CHECK_EQ(reader_fixture.runtime.proof_count(), std::size_t{0});
    PD_CHECK_EQ(reader_fixture.runtime.load(source.string()), PersistenceStatus::OK);
    PD_CHECK_EQ(reader_fixture.runtime.policy_count(), std::size_t{1});
    PD_CHECK_EQ(reader_fixture.runtime.proof_count(), std::size_t{1});
    const std::optional<DiversityProof> recovered = reader_fixture.runtime.proof(proof);
    PD_REQUIRE(recovered.has_value());
    PD_CHECK_EQ(recovered->outcome, ProofOutcome::NOT_DIVERSE);
    PD_CHECK_EQ(reader_fixture.runtime.history(proof).size(), history_size);
    PD_REQUIRE(reader_fixture.runtime.snapshot(proof).has_value());
    PD_CHECK(reader_fixture.runtime.snapshot(proof)->proof == proof);
    // Recovery restores state, never observations: a fresh runtime has not
    // evaluated anything yet.
    PD_CHECK_EQ(reader_fixture.runtime.stats().evaluations, std::uint64_t{0});
    PD_CHECK_EQ(reader_fixture.runtime.stats().commits, std::uint64_t{0});
    // The recovered store re-saves to the exact same bytes.
    PD_CHECK_EQ(reader_fixture.runtime.save(copy.string()), PersistenceStatus::OK);
    PD_CHECK(read_file(source.string()) == read_file(copy.string()));
  }
  std::error_code error;
  std::filesystem::remove(source, error);
  std::filesystem::remove(copy, error);
}

PD_TEST(atomic_replacement_never_leaves_a_partial_store) {
  const std::filesystem::path root = pd_test::unique_test_path("atomic");
  std::error_code error;
  std::filesystem::create_directories(root, error);
  PD_REQUIRE(std::filesystem::exists(root));
  const std::filesystem::path target = root / "store.pds";

  std::vector<std::uint8_t> first(64, static_cast<std::uint8_t>(0x11));
  PD_CHECK_EQ(write_store_atomic(target.string(), first), PersistenceStatus::OK);
  PD_CHECK(read_file(target.string()) == first);
  PD_CHECK_EQ(count_temporary_siblings(target), std::size_t{0});

  std::vector<std::uint8_t> second(4096, static_cast<std::uint8_t>(0x22));
  PD_CHECK_EQ(write_store_atomic(target.string(), second), PersistenceStatus::OK);
  PD_CHECK(read_file(target.string()) == second);
  PD_CHECK_EQ(count_temporary_siblings(target), std::size_t{0});

  // A destination whose parent does not exist cannot be replaced and leaves no
  // partial file behind.
  const std::filesystem::path missing = root / "absent" / "store.pds";
  PD_CHECK_EQ(write_store_atomic(missing.string(), first), PersistenceStatus::IO_FAILURE);
  PD_CHECK(!std::filesystem::exists(missing));

  // A destination that is a directory fails the replacement, the previous
  // content survives and the temporary file is removed.
  const std::filesystem::path directory_target = root / "occupied.pds";
  std::filesystem::create_directories(directory_target, error);
  PD_REQUIRE(std::filesystem::is_directory(directory_target));
  PD_CHECK_EQ(write_store_atomic(directory_target.string(), second),
              PersistenceStatus::ATOMIC_REPLACE_FAILURE);
  PD_CHECK(std::filesystem::is_directory(directory_target));
  PD_CHECK_EQ(count_temporary_siblings(directory_target), std::size_t{0});

  std::filesystem::remove_all(root, error);
}

PD_TEST(a_refused_load_leaves_the_previous_state_intact) {
  pd_test::Fixture fixture;
  const DisjointPair pair = install_pair(fixture, "dpol-recovery",
                                         {DiversityClass::LINK_DISJOINT}, "rg");
  PD_CHECK_EQ(evaluate(fixture, pair.request, "rg-1").status, MutationStatus::APPLIED);

  const std::filesystem::path path = pd_test::unique_test_path("recovery.pds");
  PD_CHECK_EQ(fixture.runtime.save(path.string()), PersistenceStatus::OK);
  const std::vector<std::uint8_t> good = read_file(path.string());
  const std::string before = fixture.runtime.render();
  const std::size_t policies_before = fixture.runtime.policy_count();
  const std::size_t proofs_before = fixture.runtime.proof_count();
  const RuntimeStats stats_before = fixture.runtime.stats();

  // A single flipped bit in the payload is refused and changes nothing.
  std::vector<std::uint8_t> corrupt = good;
  corrupt[good.size() / 2] = static_cast<std::uint8_t>(corrupt[good.size() / 2] ^ 0x40U);
  PD_REQUIRE(write_file(path.string(), corrupt));
  PD_CHECK_EQ(fixture.runtime.load(path.string()), PersistenceStatus::INTEGRITY_FAILURE);
  PD_CHECK_EQ(fixture.runtime.render(), before);
  PD_CHECK_EQ(fixture.runtime.policy_count(), policies_before);
  PD_CHECK_EQ(fixture.runtime.proof_count(), proofs_before);
  PD_CHECK(fixture.runtime.stats() == stats_before);

  // A truncated file is refused.
  std::vector<std::uint8_t> truncated(good.begin(), good.begin() + 10);
  PD_REQUIRE(write_file(path.string(), truncated));
  PD_CHECK_EQ(fixture.runtime.load(path.string()), PersistenceStatus::TRUNCATED);
  PD_CHECK_EQ(fixture.runtime.render(), before);

  // An empty file and a missing file are refused distinctly.
  PD_REQUIRE(write_file(path.string(), {}));
  PD_CHECK_EQ(fixture.runtime.load(path.string()), PersistenceStatus::EMPTY_FILE);
  std::error_code error;
  std::filesystem::remove(path, error);
  PD_CHECK_EQ(fixture.runtime.load(path.string()), PersistenceStatus::IO_FAILURE);
  PD_CHECK_EQ(fixture.runtime.render(), before);
  PD_CHECK(fixture.runtime.stats() == stats_before);

  // A store larger than the configured budget is refused before it is parsed.
  PD_REQUIRE(write_file(path.string(), good));
  Limits tiny = fixture.limits;
  tiny.max_store_bytes = good.size() - 1;
  PD_CHECK(tiny.self_consistent());
  std::vector<std::uint8_t> loaded;
  PD_CHECK_EQ(read_store_bytes(path.string(), tiny, loaded),
              PersistenceStatus::SIZE_LIMIT_EXCEEDED);
  PD_CHECK_EQ(fixture.runtime.render(), before);

  // The intact store still loads, and recovery never moves the epoch backwards:
  // the store was written at epoch 1 while the coordinator is already at 9.
  PD_CHECK_EQ(fixture.publication.restore_epoch(CoordinatorEpoch::from_value(9)),
              AuthorityStatus::ACCEPTED);
  PD_CHECK_EQ(fixture.runtime.load(path.string()), PersistenceStatus::OK);
  PD_CHECK_EQ(fixture.publication.current_epoch(), CoordinatorEpoch::from_value(9));
  PD_CHECK_EQ(fixture.runtime.policy_count(), policies_before);
  PD_CHECK_EQ(fixture.runtime.proof_count(), proofs_before);
  PD_CHECK_EQ(fixture.runtime.render(), before);

  std::filesystem::remove(path, error);
}

PD_TEST(store_section_counts_use_checked_arithmetic) {
  pd_test::Fixture fixture;
  const std::vector<std::uint8_t> empty = empty_store_bytes();
  StoreContents contents;
  std::string detail;
  PD_CHECK_EQ(decode_store(empty.data(), empty.size(), fixture.limits, contents, detail),
              PersistenceStatus::OK);
  PD_CHECK(contents.policies.empty());
  PD_CHECK(contents.snapshots.empty());

  // The same store with the first section count replaced by a declared count.
  auto store_with_policy_count = [&](std::uint64_t declared,
                                     const std::vector<std::uint8_t>& raw_count) {
    std::vector<std::uint8_t> payload(empty.begin(), empty.end() - 8);
    payload.resize(20);  // magic + version + epoch
    if (raw_count.empty()) {
      append_varint(payload, declared);
    } else {
      payload.insert(payload.end(), raw_count.begin(), raw_count.end());
    }
    // Keep the remaining six section counts so the decoder reaches the trail.
    for (int section = 0; section < 6; ++section) {
      append_varint(payload, 0);
    }
    return with_trailer(payload);
  };

  const std::vector<std::uint8_t> over_records =
      store_with_policy_count(static_cast<std::uint64_t>(fixture.limits.max_store_records) + 1, {});
  StoreContents ignored;
  PD_CHECK_EQ(decode_store(over_records.data(), over_records.size(), fixture.limits, ignored, detail),
              PersistenceStatus::RECORD_LIMIT_EXCEEDED);
  PD_CHECK(!detail.empty());

  // A count that fits the record budget but cannot fit the bytes is refused as
  // absurd rather than trusted.
  const std::vector<std::uint8_t> absurd =
      store_with_policy_count(static_cast<std::uint64_t>(fixture.limits.max_store_records), {});
  PD_CHECK_EQ(decode_store(absurd.data(), absurd.size(), fixture.limits, ignored, detail),
              PersistenceStatus::ABSURD_COUNT);

  // Eleven continuation bytes cannot encode a 64-bit count. The reader refuses
  // the encoding outright; the section-count reader reports the refusal as a
  // truncated section, which is still a refusal and never a defaulted count.
  const std::vector<std::uint8_t> runaway =
      store_with_policy_count(0, std::vector<std::uint8_t>(11, 0xffU));
  PD_CHECK_EQ(decode_store(runaway.data(), runaway.size(), fixture.limits, ignored, detail),
              PersistenceStatus::TRUNCATED);

  // The same checked arithmetic is visible on the record codec, where a varint
  // that cannot encode a 64-bit value is an invalid encoding rather than an
  // exhausted input.
  std::vector<std::uint8_t> malformed_record;
  for (int i = 0; i < 11; ++i) {
    malformed_record.push_back(0xffU);
  }
  ByteReader record_reader(malformed_record.data(), malformed_record.size());
  DiversityPolicy refused_policy;
  PD_CHECK_EQ(decode_policy(record_reader, fixture.limits, refused_policy),
              DecodeStatus::INVALID_ENCODING);

  // The declared count is also bounded by the per-store record budget.
  Limits small = fixture.limits;
  small.max_store_records = 2;
  PD_REQUIRE(small.self_consistent());
  const std::vector<std::uint8_t> three =
      store_with_policy_count(3, {});
  PD_CHECK_EQ(decode_store(three.data(), three.size(), small, ignored, detail),
              PersistenceStatus::RECORD_LIMIT_EXCEEDED);
}

PD_TEST(every_persistence_limit_is_actually_consulted) {
  // max_store_records and max_store_bytes are consulted by the store loader.
  {
    pd_test::Fixture fixture;
    const DisjointPair pair = install_pair(fixture, "dpol-limits",
                                           {DiversityClass::LINK_DISJOINT}, "lim");
    PD_CHECK_EQ(evaluate(fixture, pair.request, "lim-1").status, MutationStatus::APPLIED);
    for (int index = 0; index < 2; ++index) {
      const DiversityPolicy extra = pd_test::make_policy(
          "dpol-limits-extra-" + std::to_string(index), {DiversityClass::LINK_DISJOINT},
          EndpointExemption::NONE, 2);
      PD_CHECK_EQ(publish_policy(fixture, extra, "lim-extra-" + std::to_string(index)).status,
                  MutationStatus::APPLIED);
    }
    const std::filesystem::path path = pd_test::unique_test_path("limits.pds");
    PD_CHECK_EQ(fixture.runtime.save(path.string()), PersistenceStatus::OK);
    const std::vector<std::uint8_t> bytes = read_file(path.string());
    std::string detail;
    StoreContents contents;

    Limits roomy = fixture.limits;
    roomy.max_store_records = 4;
    PD_REQUIRE(roomy.self_consistent());
    PD_CHECK_EQ(decode_store(bytes.data(), bytes.size(), roomy, contents, detail),
                PersistenceStatus::OK);
    PD_CHECK_EQ(contents.policies.size(), std::size_t{3});

    Limits too_few = fixture.limits;
    too_few.max_store_records = 2;
    PD_REQUIRE(too_few.self_consistent());
    PD_CHECK_EQ(decode_store(bytes.data(), bytes.size(), too_few, contents, detail),
                PersistenceStatus::RECORD_LIMIT_EXCEEDED);
    PD_CHECK(detail.find("policy") != std::string::npos);

    Limits too_small = fixture.limits;
    too_small.max_store_bytes = bytes.size() - 1;
    PD_REQUIRE(too_small.self_consistent());
    PD_CHECK_EQ(decode_store(bytes.data(), bytes.size(), too_small, contents, detail),
                PersistenceStatus::SIZE_LIMIT_EXCEEDED);
    std::vector<std::uint8_t> raw;
    PD_CHECK_EQ(read_store_bytes(path.string(), too_small, raw),
                PersistenceStatus::SIZE_LIMIT_EXCEEDED);
    PD_CHECK_EQ(read_store_bytes(path.string(), fixture.limits, raw), PersistenceStatus::OK);
    PD_CHECK(raw == bytes);

    std::error_code error;
    std::filesystem::remove(path, error);
  }

  // max_persistence_record_bytes bounds a policy description on both paths.
  {
    Limits tight;
    tight.max_persistence_record_bytes = 200;
    PD_REQUIRE(tight.self_consistent());
    pd_test::Fixture fixture(tight);
    DiversityPolicy policy = pd_test::make_policy("dpol-long", {DiversityClass::LINK_DISJOINT},
                                                  EndpointExemption::NONE, 2);
    policy.description.assign(400, 'd');
    const MutationResult refused =
        fixture.runtime.publish_policy(policy, fixture.actor("long-policy"));
    PD_CHECK_EQ(refused.status, MutationStatus::MALFORMED);
    PD_CHECK(refused.detail.find("DESCRIPTION_TOO_LONG") != std::string::npos);

    // The same record is refused by the decoder, which bounds the description
    // against a quarter of the record budget.
    ByteWriter writer;
    encode_policy(writer, policy);
    ByteReader reader(writer.data().data(), writer.size());
    DiversityPolicy decoded;
    PD_CHECK_EQ(decode_policy(reader, tight, decoded), DecodeStatus::LIMIT_EXCEEDED);

    // Publishing the identical content succeeds under a budget that can hold it.
    pd_test::Fixture roomy_fixture;
    PD_CHECK_EQ(publish_policy(roomy_fixture, policy, "long-policy-roomy").status,
                MutationStatus::APPLIED);
  }

  // max_history bounds the retained revisions of one proof identity.
  {
    Limits bounded;
    bounded.max_history = 2;
    pd_test::Fixture fixture(bounded);
    const DisjointPair pair = install_pair(fixture, "dpol-history",
                                           {DiversityClass::LINK_DISJOINT}, "hist");
    for (int revision = 0; revision < 6; ++revision) {
      if (revision % 2 == 1) {
        make_pair_conflicting(fixture);
      } else {
        restore_pair_conflict_free(fixture);
      }
      const MutationResult result =
          evaluate(fixture, pair.request, "hist-" + std::to_string(revision));
      PD_CHECK_EQ(result.status, MutationStatus::APPLIED);
    }
    const std::vector<DiversityProof> history = fixture.runtime.history(pair.proof);
    PD_CHECK_EQ(history.size(), std::size_t{2});
    PD_CHECK(fixture.runtime.snapshot_ids(pair.proof).size() <= std::size_t{2});
  }
}

PD_TEST(decoding_is_byte_deterministic) {
  pd_test::Fixture fixture;
  const DisjointPair pair = install_pair(fixture, "dpol-determinism",
                                         {DiversityClass::LINK_DISJOINT}, "det");
  PD_CHECK_EQ(evaluate(fixture, pair.request, "det-1").status, MutationStatus::APPLIED);
  make_pair_conflicting(fixture);
  PD_CHECK_EQ(evaluate(fixture, pair.request, "det-2").status, MutationStatus::APPLIED);

  const std::filesystem::path first = pd_test::unique_test_path("determinism-a.pds");
  const std::filesystem::path second = pd_test::unique_test_path("determinism-b.pds");
  PD_CHECK_EQ(fixture.runtime.save(first.string()), PersistenceStatus::OK);
  PD_CHECK_EQ(fixture.runtime.save(second.string()), PersistenceStatus::OK);
  const std::vector<std::uint8_t> bytes = read_file(first.string());
  PD_CHECK(!bytes.empty());
  PD_CHECK(bytes == read_file(second.string()));

  // Encoding the same contents twice is byte-identical, and a decode followed
  // by a re-encode reproduces the original bytes exactly.
  StoreContents contents;
  std::string detail;
  PD_CHECK_EQ(decode_store(bytes.data(), bytes.size(), fixture.limits, contents, detail),
              PersistenceStatus::OK);
  const std::vector<std::uint8_t> encoded_once = encode_store(contents, fixture.limits);
  const std::vector<std::uint8_t> encoded_twice = encode_store(contents, fixture.limits);
  PD_CHECK(encoded_once == encoded_twice);
  PD_CHECK(encoded_once == bytes);

  std::error_code error;
  std::filesystem::remove(first, error);
  std::filesystem::remove(second, error);
}

PD_TEST_MAIN()
