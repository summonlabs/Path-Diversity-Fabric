// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// Core surface: strongly typed identities, generations, digests, the canonical
// byte encoding, limits, canonical ordering and every public enum encoding that
// the remaining suites depend on.

#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "test_support.hpp"

namespace {

using namespace path_diversity;

// Prints the failing context before delegating to the harness, so a failure
// inside a generated loop names the exact input that produced it.
void expect(bool condition, const std::string& context) {
  if (!condition) {
    std::cout << "  context: " << context << "\n";
  }
  pd_test::check(condition, context, __FILE__, __LINE__);
}

template <class Enum, class Render>
void check_enum_names(const char* label, std::uint8_t first, std::uint8_t last, Render render,
                      bool named_outside_range = true) {
  std::vector<std::string> names;
  for (std::uint8_t raw = first; raw <= last; ++raw) {
    const std::string text(render(static_cast<Enum>(raw)));
    const std::string where = std::string(label) + " raw " + std::to_string(raw);
    expect(!text.empty(), where + " has no name");
    expect(text != "UNKNOWN" && text != "unknown_bound", where + " is not named");
    for (const std::string& other : names) {
      expect(other != text, where + " repeats the name " + text);
    }
    names.push_back(text);
  }
  if (named_outside_range) {
    const std::string outside(render(static_cast<Enum>(static_cast<std::uint8_t>(last + 1))));
    expect(outside == "UNKNOWN", std::string(label) + " named an undefined raw as " + outside);
  }
}

// Defining range guards share one shape: every defined raw is accepted, every
// undefined raw around the range is refused.
template <class Predicate>
void check_defined_range(const char* label, std::uint8_t first, std::uint8_t last,
                         Predicate defined) {
  for (std::uint8_t raw = first; raw <= last; ++raw) {
    expect(defined(raw), std::string(label) + " refused defined raw " + std::to_string(raw));
  }
  expect(!defined(0) || first == 0, std::string(label) + " accepted raw 0");
  expect(!defined(255), std::string(label) + " accepted raw 255");
  if (last < 254) {
    expect(!defined(static_cast<std::uint8_t>(last + 1)),
           std::string(label) + " accepted raw " + std::to_string(last + 1));
  }
}

template <class Enum, class Render, class Parse>
void check_enum_parse(const char* label, std::uint8_t first, std::uint8_t last, Render render,
                      Parse parse) {
  for (std::uint8_t raw = first; raw <= last; ++raw) {
    const std::string text(render(static_cast<Enum>(raw)));
    const std::string where = std::string(label) + " raw " + std::to_string(raw);
    const std::optional<Enum> parsed = parse(text);
    expect(parsed.has_value(), where + " cannot parse back " + text);
    if (parsed.has_value()) {
      expect(static_cast<std::uint8_t>(*parsed) == raw, where + " round trip moved " + text);
    }
    expect(!parse(text + "-unknown").has_value(), where + " accepted a near miss");
    expect(!parse(std::string_view()).has_value(), where + " parsed the empty string");
  }
}

// A decoder that does not consume the whole input rejects trailing bytes.
DecodeStatus decode_strict_u32(const std::vector<std::uint8_t>& data, std::uint32_t& out) {
  ByteReader reader(data.data(), data.size());
  if (!reader.u32(out)) {
    return reader.status();
  }
  if (!reader.at_end()) {
    return DecodeStatus::TRAILING_BYTES;
  }
  return DecodeStatus::OK;
}

std::vector<PathRef> make_path_refs() {
  std::vector<PathRef> paths;
  const char* names[4] = {"path-d", "path-b", "path-a", "path-c"};
  for (const char* name : names) {
    PathRef reference;
    reference.path = PathId::parse(name);
    reference.authority_generation = PathAuthorityGeneration::from_value(1);
    paths.push_back(reference);
  }
  return paths;
}

}  // namespace

#define PD_ENUM_NAMES(label, Type, first, last) \
  check_enum_names<Type>(label, first, last, [](Type value) { return to_string(value); })
#define PD_ENUM_NAMES_LOOSE(label, Type, first, last) \
  check_enum_names<Type>(label, first, last, [](Type value) { return to_string(value); }, false)
#define PD_ENUM_PARSE(label, Type, first, last, parse)                     \
  check_enum_parse<Type>(label, first, last,                               \
                         [](Type value) { return to_string(value); }, parse)

PD_TEST(string_id_parse_and_reject) {
  const PathId path = PathId::parse("path-a.1");
  PD_CHECK(path.valid());
  PD_CHECK(static_cast<bool>(path));
  PD_CHECK_EQ(path.str(), std::string("path-a.1"));
  PD_CHECK_EQ(path.view(), std::string_view("path-a.1"));
  PD_CHECK_EQ(PathId::type_name(), std::string_view("PathId"));
  PD_CHECK(!PathId().valid());
  PD_CHECK(!static_cast<bool>(PathId()));

  const PathId again = PathId::parse("path-a.1");
  PD_CHECK(path == again);
  PD_CHECK_EQ(path.hash(), again.hash());
  PD_CHECK(!(path < again));
  PD_CHECK(PathId::parse("path-a") < PathId::parse("path-b"));
  PD_CHECK(PathId::parse("path-b") > PathId::parse("path-a"));

  PD_CHECK(!PathId::try_parse("").has_value());
  PD_CHECK(!PathId::try_parse("has space").has_value());
  PD_CHECK(!PathId::try_parse("has\ttab").has_value());
  PD_CHECK(!PathId::try_parse("has\"quote").has_value());
  PD_CHECK(!PathId::try_parse("has\\slash").has_value());
  PD_CHECK(!PathId::try_parse("has,comma").has_value());
  PD_CHECK(!PathId::try_parse("caf\xc3\xa9").has_value());
  PD_CHECK(PathId::from_wire("ok-1").has_value());
  PD_CHECK(!PathId::from_wire("not ok").has_value());

  std::string longest(PathId::max_length, 'a');
  PD_CHECK(PathId::try_parse(longest).has_value());
  longest.push_back('a');
  PD_CHECK(!PathId::try_parse(longest).has_value());
  PD_CHECK(LinkId::try_parse(std::string(LinkId::max_length, 'z')).has_value());
  PD_CHECK(!LinkId::try_parse(std::string(LinkId::max_length + 1, 'z')).has_value());
  PD_CHECK(WorkerBootId::try_parse(std::string(WorkerBootId::max_length, 'b')).has_value());
  PD_CHECK(!WorkerBootId::try_parse(std::string(WorkerBootId::max_length + 1, 'b')).has_value());
  PD_CHECK(PathId::try_parse("abzAZ09._-:/#@+").has_value());

  bool threw = false;
  try {
    (void)PathId::parse("bad id");
  } catch (const IdentityError&) {
    threw = true;
  }
  PD_CHECK(threw);

  // Distinct tags are distinct types: no cross-domain assignment compiles.
  static_assert(!std::is_same_v<PathId, NodeId>);
  static_assert(!std::is_same_v<LinkId, DeviceId>);
  static_assert(!std::is_same_v<PathSetId, DiversityProofId>);
  PD_CHECK_EQ(NodeId::type_name(), std::string_view("NodeId"));
  PD_CHECK_EQ(MutationAttemptId::type_name(), std::string_view("MutationAttemptId"));

  std::unordered_map<PathId, int, StringIdHash<PathIdTag, PathId::max_length>> index;
  index[path] = 7;
  index[PathId::parse("path-z")] = 9;
  PD_CHECK_EQ(index.size(), std::size_t{2});
  PD_CHECK_EQ(index[again], 7);
}

PD_TEST(generation_semantics) {
  const PathAuthorityGeneration unset;
  PD_CHECK(!unset.is_set());
  PD_CHECK(!static_cast<bool>(unset));
  PD_CHECK_EQ(unset.value(), std::uint64_t{0});
  PD_CHECK(unset == PathAuthorityGeneration::from_value(0));
  PD_CHECK(!PathAuthorityGeneration::from_wire(0).has_value());
  PD_CHECK(PathAuthorityGeneration::from_wire(1).has_value());
  PD_CHECK_EQ(PathAuthorityGeneration::from_wire(9)->value(), std::uint64_t{9});

  const PathAuthorityGeneration one = PathAuthorityGeneration::from_value(1);
  PD_CHECK(one.is_set());
  PD_CHECK_EQ(one.next().value(), std::uint64_t{2});
  PD_CHECK(one < one.next());
  PD_CHECK(one.next() > one);
  PD_CHECK(one == PathAuthorityGeneration::from_value(1));
  PD_CHECK_EQ(GenerationHash<PathAuthorityGenerationTag>{}(one),
              GenerationHash<PathAuthorityGenerationTag>{}(PathAuthorityGeneration::from_value(1)));
  PD_CHECK_EQ(PathAuthorityGeneration::type_name(), std::string_view("PathAuthorityGeneration"));
  PD_CHECK(PathAuthorityGeneration::can_advance(0));
  PD_CHECK(PathAuthorityGeneration::can_advance(1));
  PD_CHECK(!PathAuthorityGeneration::can_advance(static_cast<std::uint64_t>(-1)));
  static_assert(!std::is_same_v<PathAuthorityGeneration, TopologyGeneration>);
  PD_CHECK_EQ(TopologyGeneration::type_name(), std::string_view("TopologyGeneration"));
  PD_CHECK(!CoordinatorEpoch::from_value(0).is_set());
}

PD_TEST(digest_determinism_and_sensitivity) {
  const std::uint8_t first[4] = {0x04, 0x03, 0x02, 0x01};
  const std::uint8_t other[4] = {0x05, 0x03, 0x02, 0x01};
  const Digest base = Digest::of(first, 4);
  PD_CHECK(base == Digest::of(first, 4));
  PD_CHECK_EQ(base.hex(), Digest::of(first, 4).hex());
  PD_CHECK_EQ(base.hex().size(), std::size_t{32});
  PD_CHECK(base.hex().find_first_not_of("0123456789abcdef") == std::string::npos);
  PD_CHECK(!(base == Digest::of(other, 4)));
  PD_CHECK(!(base == Digest::of(first, 3)));
  PD_CHECK(!(base == Digest::of(nullptr, 0)));
  PD_CHECK(Digest::of(nullptr, 0) == Digest::of(nullptr, 0));
  PD_CHECK(Digest::of(first, 4) < Digest::of(other, 4));
  PD_CHECK(!(Digest::of(other, 4) < Digest::of(first, 4)));

  std::uint64_t folded = 0;
  for (int i = 0; i < 8; ++i) {
    folded |= static_cast<std::uint64_t>(base.bytes()[static_cast<std::size_t>(i)]) << (8 * i);
  }
  PD_CHECK_EQ(base.low64(), folded);
  PD_CHECK_EQ(DigestHash{}(base), DigestHash{}(Digest::of(first, 4)));
  std::unordered_map<Digest, int, DigestHash> digests;
  digests[base] = 1;
  digests[Digest::of(other, 4)] = 2;
  PD_CHECK_EQ(digests.size(), std::size_t{2});
  PD_CHECK_EQ(digests[Digest::of(first, 4)], 1);

  // The incremental surface is the same function as the one-shot entry point.
  Digest chained;
  chained.update_u32(0x01020304U);
  Digest raw;
  raw.update(first, 4);
  PD_CHECK(chained == raw);

  // Length prefixing keeps concatenations distinct from single strings.
  Digest whole;
  whole.update_text("ab");
  Digest split;
  split.update_text("a");
  split.update_text("b");
  PD_CHECK(!(whole == split));
  Digest prefixed;
  prefixed.update_bytes(first, 4);
  Digest bare;
  bare.update(first, 4);
  PD_CHECK(!(prefixed == bare));
  PD_CHECK_EQ(mint_prefixed("pset-", base), std::string("pset-") + base.hex());
}

PD_TEST(byte_encoding_round_trip) {
  ByteWriter writer;
  writer.u8(0x7fU);
  writer.u16(0xbeefU);
  writer.u32(0xdeadbeefU);
  writer.u64(0x0123456789abcdefULL);
  writer.varint(300);
  writer.text("hello");
  writer.boolean(true);
  writer.boolean(false);
  PD_CHECK_EQ(writer.size(), writer.data().size());

  ByteReader reader(writer.data().data(), writer.size());
  std::uint8_t byte = 0;
  std::uint16_t short_value = 0;
  std::uint32_t word = 0;
  std::uint64_t long_value = 0;
  std::uint64_t varint_value = 0;
  std::string text;
  bool flag = false;
  PD_CHECK(reader.u8(byte));
  PD_CHECK_EQ(byte, std::uint8_t{0x7f});
  PD_CHECK(reader.u16(short_value));
  PD_CHECK_EQ(short_value, std::uint16_t{0xbeef});
  PD_CHECK(reader.u32(word));
  PD_CHECK_EQ(word, std::uint32_t{0xdeadbeef});
  PD_CHECK(reader.u64(long_value));
  PD_CHECK_EQ(long_value, std::uint64_t{0x0123456789abcdef});
  PD_CHECK(reader.varint(varint_value));
  PD_CHECK_EQ(varint_value, std::uint64_t{300});
  PD_CHECK(reader.text(text, 64));
  PD_CHECK_EQ(text, std::string("hello"));
  PD_CHECK(reader.boolean(flag));
  PD_CHECK(flag);
  PD_CHECK(reader.boolean(flag));
  PD_CHECK(!flag);
  PD_CHECK(reader.at_end());
  PD_CHECK_EQ(reader.remaining(), std::size_t{0});
  PD_CHECK(reader.status() == DecodeStatus::OK);

  // Endianness is fixed little-endian: the bytes are the contract.
  ByteWriter little;
  little.u32(0x01020304U);
  PD_CHECK_EQ(little.data().size(), std::size_t{4});
  PD_CHECK_EQ(little.data()[0], std::uint8_t{0x04});
  PD_CHECK_EQ(little.data()[3], std::uint8_t{0x01});

  // A zero-length byte string is self-delimiting and consumes one byte.
  ByteWriter empty;
  empty.text("");
  PD_CHECK_EQ(empty.size(), std::size_t{1});
  ByteReader empty_reader(empty.data().data(), empty.size());
  std::string decoded;
  PD_CHECK(empty_reader.text(decoded, 0));
  PD_CHECK_EQ(decoded, std::string());
  PD_CHECK(empty_reader.at_end());
}

PD_TEST(varint_boundaries) {
  struct Case {
    std::uint64_t value;
    std::size_t encoded_size;
  };
  const Case cases[11] = {{0, 1},
                          {1, 1},
                          {127, 1},
                          {128, 2},
                          {255, 2},
                          {16383, 2},
                          {16384, 3},
                          {2097151, 3},
                          {2097152, 4},
                          {0xffffffffULL, 5},
                          {0xffffffffffffffffULL, 10}};
  for (const Case& item : cases) {
    const std::string where = "varint " + std::to_string(item.value);
    ByteWriter writer;
    writer.varint(item.value);
    expect(writer.size() == item.encoded_size,
           where + " encoded to " + std::to_string(writer.size()) + " bytes");
    ByteReader reader(writer.data().data(), writer.size());
    std::uint64_t decoded = 0;
    expect(reader.varint(decoded), where + " did not decode");
    expect(decoded == item.value, where + " round trip moved to " + std::to_string(decoded));
    expect(reader.at_end(), where + " left bytes behind");
    expect(reader.status() == DecodeStatus::OK, where + " reported a failure status");
  }
}

PD_TEST(decoding_rejects_truncation_and_overrun) {
  ByteWriter writer;
  writer.u64(0x1122334455667788ULL);
  const std::vector<std::uint8_t> encoded = writer.data();
  for (std::size_t cut = 0; cut + 1 < encoded.size(); ++cut) {
    ByteReader reader(encoded.data(), cut);
    std::uint64_t value = 0;
    expect(!reader.u64(value), "u64 decoded from a buffer of " + std::to_string(cut) + " bytes");
    expect(reader.status() == DecodeStatus::TRUNCATED, "truncation was not reported as TRUNCATED");
  }
  ByteReader exact(encoded.data(), encoded.size());
  std::uint64_t value = 0;
  PD_CHECK(exact.u64(value));
  PD_CHECK_EQ(value, std::uint64_t{0x1122334455667788});
  PD_CHECK(exact.at_end());

  // A length that claims more bytes than the frame holds is LENGTH_OVERRUN.
  ByteWriter framed;
  framed.text("0123456789");
  ByteReader overrun(framed.data().data(), 3);
  std::string out;
  PD_CHECK(!overrun.text(out, 64));
  PD_CHECK(overrun.status() == DecodeStatus::LENGTH_OVERRUN);
  PD_CHECK(!overrun.text(out, 64));
  PD_CHECK(overrun.status() == DecodeStatus::LENGTH_OVERRUN);

  // A length beyond the caller's bound is LIMIT_EXCEEDED, not a length error.
  ByteReader limited(framed.data().data(), framed.size());
  PD_CHECK(!limited.text(out, 4));
  PD_CHECK(limited.status() == DecodeStatus::LIMIT_EXCEEDED);

  // Ten continuation bytes cannot encode a 64-bit value.
  const std::vector<std::uint8_t> runaway(11, 0xffU);
  ByteReader bad_varint(runaway.data(), runaway.size());
  std::uint64_t ignored = 0;
  PD_CHECK(!bad_varint.varint(ignored));
  PD_CHECK(bad_varint.status() == DecodeStatus::INVALID_ENCODING);

  // A boolean that is neither 0 nor 1 is refused rather than coerced.
  ByteWriter boolean_writer;
  boolean_writer.u8(2);
  ByteReader bad_boolean(boolean_writer.data().data(), boolean_writer.size());
  bool flag = false;
  PD_CHECK(!bad_boolean.boolean(flag));
  PD_CHECK(bad_boolean.status() == DecodeStatus::INVALID_ENCODING);

  ByteWriter single;
  single.u32(1);
  std::uint32_t decoded = 0;
  PD_CHECK(decode_strict_u32(single.data(), decoded) == DecodeStatus::OK);
  PD_CHECK_EQ(decoded, std::uint32_t{1});
  ByteWriter words;
  words.u32(1);
  words.u8(0);
  PD_CHECK(decode_strict_u32(words.data(), decoded) == DecodeStatus::TRAILING_BYTES);
  PD_CHECK_EQ(to_string(DecodeStatus::TRAILING_BYTES), std::string_view("TRAILING_BYTES"));
  PD_CHECK_EQ(to_string(DecodeStatus::LENGTH_OVERRUN), std::string_view("LENGTH_OVERRUN"));
  PD_CHECK_EQ(to_string(DecodeStatus::INVALID_ENCODING), std::string_view("INVALID_ENCODING"));
  PD_CHECK_EQ(to_string(static_cast<DecodeStatus>(200)), std::string_view("UNKNOWN"));
}

PD_TEST(canonical_ordering_and_uniqueness) {
  std::vector<NodeId> nodes = {NodeId::parse("node-c"), NodeId::parse("node-a"),
                               NodeId::parse("node-b"), NodeId::parse("node-a")};
  PD_CHECK(has_duplicates(nodes));
  canonical_sort_unique(nodes);
  PD_CHECK_EQ(nodes.size(), std::size_t{3});
  PD_CHECK_EQ(nodes[0].str(), std::string("node-a"));
  PD_CHECK_EQ(nodes[1].str(), std::string("node-b"));
  PD_CHECK_EQ(nodes[2].str(), std::string("node-c"));
  PD_CHECK(!has_duplicates(nodes));
  PD_CHECK(!has_duplicates(std::vector<NodeId>()));

  std::vector<PathRef> shuffled = make_path_refs();
  std::vector<PathRef> expected = shuffled;
  canonical_path_order(expected);
  canonical_path_order(shuffled);
  PD_CHECK(shuffled == expected);
  PD_CHECK_EQ(shuffled.front().path.str(), std::string("path-a"));
  PD_CHECK_EQ(shuffled.back().path.str(), std::string("path-d"));
  PD_CHECK_EQ(shuffled.front().render(), std::string("path-a@pa1"));
  PD_CHECK(!has_duplicate_paths(shuffled));

  // Proof identity is taken over the canonical order: a permutation that is
  // canonicalized first yields one identity, which is what makes arrival order
  // irrelevant to every digest downstream.
  std::vector<PathRef> reordered = {shuffled[3], shuffled[1], shuffled[0], shuffled[2]};
  canonical_path_order(reordered);
  const Digest canonical_digest = path_set_digest(shuffled);
  PD_CHECK(path_set_digest(shuffled) == canonical_digest);
  PD_CHECK(path_set_digest(reordered) == canonical_digest);
  PD_CHECK_EQ(path_set_id(shuffled).str(), path_set_id(reordered).str());
  PD_CHECK(path_set_id(shuffled) == derived_path_set_id(canonical_digest));
  PD_CHECK_EQ(path_set_id(shuffled).str().rfind("pset-", 0), std::size_t{0});

  std::vector<PathRef> regressed = shuffled;
  regressed[0].authority_generation = PathAuthorityGeneration::from_value(2);
  canonical_path_order(regressed);
  PD_CHECK(!(path_set_digest(regressed) == canonical_digest));
  PD_CHECK(!(path_set_id(regressed) == path_set_id(shuffled)));

  std::vector<PathRef> duplicated = shuffled;
  duplicated.push_back(shuffled[0]);
  PD_CHECK(has_duplicate_paths(duplicated));
  duplicated[0].authority_generation = PathAuthorityGeneration::from_value(5);
  PD_CHECK(has_duplicate_paths(duplicated));
}

PD_TEST(proof_request_canonicalization) {
  ProofRequest request;
  request.policy = DiversityPolicyId::parse("dpol-core");
  request.policy_generation = DiversityPolicyGeneration::from_value(1);
  const std::vector<PathRef> ordered = make_path_refs();
  request.paths = {ordered[3], ordered[0], ordered[2], ordered[1]};
  PD_CHECK(request.canonicalize());
  PD_CHECK_EQ(request.paths.size(), std::size_t{4});
  PD_CHECK_EQ(request.paths[0].path.str(), std::string("path-a"));
  PD_CHECK_EQ(request.paths[3].path.str(), std::string("path-d"));

  ProofRequest permuted = request;
  permuted.paths = {ordered[1], ordered[3], ordered[0], ordered[2]};
  PD_CHECK(permuted.canonicalize());
  PD_CHECK(permuted == request);
  PD_CHECK(request.digest() == permuted.digest());
  PD_CHECK_EQ(request.path_set().str(), permuted.path_set().str());
  PD_CHECK_EQ(proof_identity(request).str(), proof_identity(permuted).str());
  PD_CHECK_EQ(proof_identity(request).str().rfind("dproof-", 0), std::size_t{0});

  ProofRequest duplicate;
  duplicate.policy = request.policy;
  duplicate.policy_generation = request.policy_generation;
  duplicate.paths = {ordered[0], ordered[0], ordered[1]};
  PD_CHECK(!duplicate.canonicalize());

  ProofRequest other_policy = request;
  other_policy.policy_generation = DiversityPolicyGeneration::from_value(2);
  PD_CHECK(!(other_policy.digest() == request.digest()));

  PD_CHECK_EQ(default_scope().str(), std::string("scope-default"));
  PD_CHECK(default_scope().valid());
  const Digest payload = request.digest();
  PD_CHECK_EQ(derived_proof_id(payload).str(), std::string("dproof-") + payload.hex());
  PD_CHECK_EQ(derived_snapshot_id(payload).str(), std::string("dsnap-") + payload.hex());
  PD_CHECK_EQ(derived_policy_id(payload).str(), std::string("dpol-") + payload.hex());
}

PD_TEST(limits_self_consistency_and_bounds) {
  const Limits defaults;
  PD_CHECK(defaults.self_consistent());
  const std::string rendered = defaults.render();

  // Every bound is named by render() and every bound that is zeroed refuses to
  // describe its own subject: a limit that cannot express its subject is a
  // defect, never a silent clamp.
  struct Bound {
    const char* name;
    std::uint32_t Limits::* member;
  };
  const Bound bounds[22] = {{"max_policies", &Limits::max_policies},
                            {"max_proofs", &Limits::max_proofs},
                            {"max_paths_per_proof", &Limits::max_paths_per_proof},
                            {"max_required_classes", &Limits::max_required_classes},
                            {"max_conflicts_per_proof", &Limits::max_conflicts_per_proof},
                            {"max_pairwise_cells", &Limits::max_pairwise_cells},
                            {"max_domain_evidence_entries", &Limits::max_domain_evidence_entries},
                            {"max_query_results", &Limits::max_query_results},
                            {"max_history", &Limits::max_history},
                            {"max_batch_size", &Limits::max_batch_size},
                            {"max_publishers", &Limits::max_publishers},
                            {"max_frame_bytes", &Limits::max_frame_bytes},
                            {"max_persistence_record_bytes", &Limits::max_persistence_record_bytes},
                            {"max_explanation_entries", &Limits::max_explanation_entries},
                            {"max_k_subset_paths", &Limits::max_k_subset_paths},
                            {"max_snapshot_paths", &Limits::max_snapshot_paths},
                            {"max_identity_length", &Limits::max_identity_length},
                            {"max_attempts_tracked", &Limits::max_attempts_tracked},
                            {"max_wire_assembly_bytes", &Limits::max_wire_assembly_bytes},
                            {"max_store_records", &Limits::max_store_records},
                            {"max_diff_entries", &Limits::max_diff_entries},
                            {"max_topology_dependencies", &Limits::max_topology_dependencies}};
  for (const Bound& bound : bounds) {
    expect(rendered.find(bound.name) != std::string::npos,
           std::string("render() omits the bound ") + bound.name);
    Limits zeroed = defaults;
    zeroed.*(bound.member) = 0;
    expect(!zeroed.self_consistent(),
           std::string("a zeroed ") + bound.name + " reported self-consistent limits");
  }
  PD_CHECK(rendered.find("max_store_bytes") != std::string::npos);
  Limits broken = defaults;
  broken.max_store_bytes = 0;
  PD_CHECK(!broken.self_consistent());
  broken = defaults;
  broken.max_wire_assembly_bytes = defaults.max_frame_bytes - 1;
  PD_CHECK(!broken.self_consistent());

  // Relational invariants: a bound that cannot express its own subject.
  const std::uint64_t exact_cells =
      static_cast<std::uint64_t>(defaults.max_paths_per_proof) *
      (static_cast<std::uint64_t>(defaults.max_paths_per_proof) - 1ULL) / 2ULL;
  broken = defaults;
  broken.max_pairwise_cells = static_cast<std::uint32_t>(exact_cells - 1ULL);
  PD_CHECK(!broken.self_consistent());
  broken = defaults;
  broken.max_pairwise_cells = static_cast<std::uint32_t>(exact_cells);
  PD_CHECK(broken.self_consistent());
  broken = defaults;
  broken.max_k_subset_paths = defaults.max_paths_per_proof + 1;
  PD_CHECK(!broken.self_consistent());
  broken = defaults;
  broken.max_snapshot_paths = defaults.max_paths_per_proof + 1;
  PD_CHECK(!broken.self_consistent());
  broken = defaults;
  broken.max_wire_assembly_bytes = defaults.max_frame_bytes;
  PD_CHECK(broken.self_consistent());

  ResourceLimitNotice notice;
  notice.bound = ResourceBound::MAX_PATHS_PER_PROOF;
  notice.observed = 70;
  notice.allowed = 64;
  const std::string text = notice.render();
  PD_CHECK(text.find("max_paths_per_proof") != std::string::npos);
  PD_CHECK(text.find("70") != std::string::npos);
  PD_CHECK(text.find("64") != std::string::npos);
  PD_CHECK_EQ(to_string(ResourceBound::MAX_PROOFS), std::string_view("max_proofs"));
  PD_CHECK_EQ(to_string(ResourceBound::MAX_DIFF_ENTRIES), std::string_view("max_diff_entries"));
  PD_CHECK_EQ(to_string(static_cast<ResourceBound>(0)), std::string_view("unknown_bound"));
  PD_CHECK_EQ(to_string(static_cast<ResourceBound>(200)), std::string_view("unknown_bound"));
  check_defined_range("ResourceBound", 1, 23, &is_defined_resource_bound);
}

PD_TEST(enum_encodings_round_trip) {
  PD_ENUM_NAMES("EntityKind", EntityKind, 1, 4);
  PD_ENUM_NAMES("DomainRelation", DomainRelation, 1, 7);
  PD_ENUM_NAMES("EvidenceCoverage", EvidenceCoverage, 1, 3);
  PD_ENUM_NAMES("DiversityClass", DiversityClass, 1, 8);
  PD_ENUM_NAMES("EndpointExemption", EndpointExemption, 1, 5);
  PD_ENUM_NAMES("SetSemantics", SetSemantics, 1, 2);
  PD_ENUM_NAMES("CompletenessRequirement", CompletenessRequirement, 1, 2);
  PD_ENUM_NAMES("UnknownBehavior", UnknownBehavior, 1, 2);
  PD_ENUM_NAMES("ProofOutcome", ProofOutcome, 1, 11);
  PD_ENUM_NAMES("ConflictClass", ConflictClass, 1, 14);
  PD_ENUM_NAMES("LifecycleState", LifecycleState, 1, 7);
  PD_ENUM_NAMES("Currentness", Currentness, 1, 9);
  PD_ENUM_NAMES("MutationStatus", MutationStatus, 1, 14);
  PD_ENUM_NAMES("AuthorityStatus", AuthorityStatus, 1, 10);
  PD_ENUM_NAMES("PolicyStatus", PolicyStatus, 0, 13);
  PD_ENUM_NAMES("ExplanationKind", ExplanationKind, 1, 16);
  PD_ENUM_NAMES("DiffKind", DiffKind, 1, 18);
  PD_ENUM_NAMES_LOOSE("ResourceBound", ResourceBound, 1, 23);
  PD_ENUM_NAMES("DecodeStatus", DecodeStatus, 0, 5);

  PD_ENUM_PARSE("DiversityClass", DiversityClass, 1, 8, &diversity_class_from_string);
  PD_ENUM_PARSE("EndpointExemption", EndpointExemption, 1, 5, &endpoint_exemption_from_string);
  PD_ENUM_PARSE("SetSemantics", SetSemantics, 1, 2, &set_semantics_from_string);
  PD_ENUM_PARSE("CompletenessRequirement", CompletenessRequirement, 1, 2,
                &completeness_requirement_from_string);
  PD_ENUM_PARSE("UnknownBehavior", UnknownBehavior, 1, 2, &unknown_behavior_from_string);
  PD_ENUM_PARSE("ProofOutcome", ProofOutcome, 1, 11, &proof_outcome_from_string);

  check_defined_range("EntityKind", 1, 4, &is_defined_entity_kind);
  check_defined_range("DomainRelation", 1, 7, &is_defined_domain_relation);
  check_defined_range("EvidenceCoverage", 1, 3, &is_defined_coverage);
  check_defined_range("DiversityClass", 1, 8, &is_defined_diversity_class);
  check_defined_range("EndpointExemption", 1, 5, &is_defined_endpoint_exemption);
  check_defined_range("SetSemantics", 1, 2, &is_defined_set_semantics);
  check_defined_range("CompletenessRequirement", 1, 2, &is_defined_completeness_requirement);
  check_defined_range("UnknownBehavior", 1, 2, &is_defined_unknown_behavior);
  check_defined_range("ProofOutcome", 1, 11, &is_defined_proof_outcome);
  check_defined_range("ConflictClass", 1, 14, &is_defined_conflict_class);
  check_defined_range("LifecycleState", 1, 7, &is_defined_lifecycle_state);
  check_defined_range("Currentness", 1, 9, &is_defined_currentness);
  check_defined_range("MutationStatus", 1, 14, &is_defined_mutation_status);
  check_defined_range("AuthorityStatus", 1, 10, &is_defined_authority_status);
  check_defined_range("ExplanationKind", 1, 16, &is_defined_explanation_kind);
  check_defined_range("DiffKind", 1, 18, &is_defined_diff_kind);
}

PD_TEST(conflict_relation_mapping_and_predicates) {
  for (std::uint8_t raw = 1; raw <= 7; ++raw) {
    const DomainRelation relation = static_cast<DomainRelation>(raw);
    const ConflictClass klass = conflict_class_for_relation(relation);
    const std::string where = std::string("relation ") + std::string(to_string(relation));
    expect(is_defined_conflict_class(static_cast<std::uint8_t>(klass)), where + " mapped nowhere");
    const std::optional<DomainRelation> round_trip = relation_for_conflict_class(klass);
    expect(round_trip.has_value(), where + " has no conflict class");
    if (round_trip.has_value()) {
      expect(*round_trip == relation, where + " round trip moved");
    }
  }
  PD_CHECK(conflict_class_for_relation(DomainRelation::FAILURE_DOMAIN) ==
           ConflictClass::SHARED_FAILURE_DOMAIN);
  PD_CHECK(!relation_for_conflict_class(ConflictClass::SHARED_LINK).has_value());
  PD_CHECK(!relation_for_conflict_class(ConflictClass::STALE_DEPENDENCY).has_value());

  PD_CHECK(outcome_asserts_independence(ProofOutcome::PROVEN_DIVERSE));
  PD_CHECK(!outcome_asserts_independence(ProofOutcome::NOT_DIVERSE));
  PD_CHECK(!outcome_asserts_independence(ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE));
  PD_CHECK(outcome_asserts_conflict(ProofOutcome::NOT_DIVERSE));
  PD_CHECK(!outcome_asserts_conflict(ProofOutcome::PROVEN_DIVERSE));
  PD_CHECK(outcome_is_decisive(ProofOutcome::PROVEN_DIVERSE));
  PD_CHECK(outcome_is_decisive(ProofOutcome::NOT_DIVERSE));
  PD_CHECK(!outcome_is_decisive(ProofOutcome::UNKNOWN_INCOMPLETE_EVIDENCE));
  PD_CHECK(!outcome_is_decisive(ProofOutcome::STALE_TOPOLOGY));
  PD_CHECK(!outcome_is_decisive(ProofOutcome::RESOURCE_LIMIT));

  PD_CHECK(mutation_status_is_success(MutationStatus::APPLIED));
  PD_CHECK(mutation_status_is_success(MutationStatus::IDEMPOTENT));
  PD_CHECK(mutation_status_is_success(MutationStatus::UNCHANGED));
  PD_CHECK(!mutation_status_is_success(MutationStatus::ILLEGAL_TRANSITION));
  PD_CHECK(authority_status_is_success(AuthorityStatus::ACCEPTED));
  PD_CHECK(authority_status_is_success(AuthorityStatus::IDEMPOTENT));
  PD_CHECK(!authority_status_is_success(AuthorityStatus::UNAUTHORIZED));
  PD_CHECK(authority_status_needs_demotion(AuthorityStatus::FENCED_PUBLISHER));
  PD_CHECK(authority_status_needs_demotion(AuthorityStatus::STALE_EPOCH));
  PD_CHECK(!authority_status_needs_demotion(AuthorityStatus::ATTEMPT_CONFLICT));

  PD_CHECK(is_domain_backed(DiversityClass::RACK_DISJOINT));
  PD_CHECK(is_domain_backed(DiversityClass::FAILURE_DOMAIN_DISJOINT));
  PD_CHECK(!is_domain_backed(DiversityClass::LINK_DISJOINT));
  PD_CHECK(!is_domain_backed(DiversityClass::SHARED_RISK_GROUP_DISJOINT));
  PD_CHECK_EQ(required_domain_relations(DiversityClass::RACK_DISJOINT).size(), std::size_t{1});
  PD_CHECK(required_domain_relations(DiversityClass::LINK_DISJOINT).empty());
  PD_CHECK(required_domain_relations(DiversityClass::FAILURE_DOMAIN_DISJOINT).empty());
}

PD_TEST(version_surface) {
  PD_CHECK_EQ(library_name(), std::string_view("Path Diversity Fabric"));
  PD_CHECK_EQ(version_string(), std::string_view("1.0.0"));
  const std::string report = version_report();
  PD_CHECK(report.find("Path Diversity Fabric") != std::string::npos);
  PD_CHECK(report.find("1.0.0") != std::string::npos);
  PD_CHECK(report.find("rule set") != std::string::npos);
  PD_CHECK_EQ(kCanonicalEncodingVersion, 1U);
  PD_CHECK_EQ(kVersionMajor, 1);
  PD_CHECK_EQ(kVersionMinor, 0);
  PD_CHECK_EQ(kVersionPatch, 0);
}

PD_TEST_MAIN()
