// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.

// path_diversity: deterministic operator tool over the public API. Every scenario it builds is
// SYNTHETIC: fabricated topology, fabricated placement and fabricated failure domains. Nothing it
// prints is evidence about a physical fabric and nothing it prints is a performance guarantee.
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "path_diversity/path_diversity.hpp"

namespace {

using namespace path_diversity;

constexpr std::uint64_t kSeed = 20260101ULL;

void print_usage(std::ostream& out) {
  out << "usage: path_diversity <command> [policy-name] [options]\n"
         "commands: version | selftest | explain <policy-name> | evaluate <policy-name> | render\n"
         "policy-name: link | transit-node | device | failure-domain | synthetic | at-least-k | incomplete\n"
         "  --pdk <path>   save the runtime store to <path> after the command\n"
         "  --load <path>  load a runtime store from <path> first; the command then reports the first\n"
         "                 proof bound to the selected policy, or the first stored proof\n"
         "  --json         print the deterministic machine-readable rendering\n"
         "exit codes: 0 success, 1 failed assertion, 2 usage error, 3 runtime failure.\n";
}

std::string jtext(const std::string& value) {
  static const char* digits = "0123456789abcdef";
  std::string out = "\"";
  for (char raw : value) {
    const unsigned char character = static_cast<unsigned char>(raw);
    if (character == '"') { out += "\\\""; }
    else if (character == '\\') { out += "\\\\"; }
    else if (character == '\n') { out += "\\n"; }
    else if (character == '\r') { out += "\\r"; }
    else if (character == '\t') { out += "\\t"; }
    else if (character < 0x20) { out += "\\u00"; out += digits[(character >> 4) & 0x0fu]; out += digits[character & 0x0fu]; }
    else { out += raw; }
  }
  return out + "\"";
}
// Fragments are already-rendered JSON. The object helper zips flat key/value pairs so every printed
// document has exactly one deterministic shape.
using Frag = std::vector<std::string>;
std::string jnum(std::uint64_t value) { return std::to_string(value); }
std::string jbool(bool value) { return value ? "true" : "false"; }
template <class T> std::string jenum(T value) { return jtext(std::string(to_string(value))); }
std::string jarr(const Frag& items) {
  std::string out = "[";
  for (std::size_t i = 0; i < items.size(); ++i) { out += i == 0 ? "" : ","; out += items[i]; }
  return out + "]";
}
std::string jobj(const Frag& fields) {
  std::string out = "{";
  for (std::size_t i = 0; i + 1 < fields.size(); i += 2) { out += i == 0 ? "" : ","; out += jtext(fields[i]) + ":" + fields[i + 1]; }
  return out + "}";
}
void print_version(bool json) {
  const Frag fields = {"command", jtext("version"), "library", jtext(std::string(library_name())), "version",
                       jtext(std::string(version_string())), "persistence_format", jnum(kPersistenceFormatVersion), "canonical_encoding", jnum(kCanonicalEncodingVersion), "digest_scheme", jnum(kDigestSchemeVersion),
                       "wire_protocol", jnum(kWireProtocolVersion), "rule_set", jnum(kDiversityRuleSetVersion)};
  std::cout << (json ? jobj(fields) : version_report()) << "\n";
}

struct Options { std::string command, policy_name, pdk_path, load_path; bool json = false; };
// Returns false for every usage error: unknown option, missing option value, missing command,
// missing policy name and unexpected positional argument.
bool parse_options(int argc, char** argv, Options& out) {
  std::vector<std::string> positional;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--json") { out.json = true; }
    else if (argument == "--pdk" || argument == "--load") {
      if (index + 1 >= argc) { std::cerr << "path_diversity: " << argument << " requires a path\n"; return false; }
      (argument == "--pdk" ? out.pdk_path : out.load_path) = argv[++index];
    } else if (!argument.empty() && argument[0] == '-') { std::cerr << "path_diversity: unknown option " << argument << "\n"; return false; }
    else { positional.push_back(argument); }
  }
  if (positional.empty()) { std::cerr << "path_diversity: no command given\n"; return false; }
  out.command = positional[0];
  if ((out.command == "explain" || out.command == "evaluate") && positional.size() < 2) {
    std::cerr << "path_diversity: " << out.command << " requires a policy name\n";
    return false;
  }
  if (positional.size() > 2) { std::cerr << "path_diversity: unexpected argument " << positional[2] << "\n"; return false; }
  if (positional.size() == 2) { out.policy_name = positional[1]; }
  return true;
}

struct Profile { DiversityPolicy policy; SyntheticFabricOptions fabric; std::uint32_t path_count = 4; };
std::optional<Profile> profile_for(const std::string& name) {
  Profile profile;
  profile.fabric.spine_count = 2; profile.fabric.leaf_count = 4; profile.fabric.racks = 2;
  profile.fabric.pods = 2; profile.fabric.sites = 1; profile.fabric.paths_per_pair = 1;
  profile.fabric.complete_domain_coverage = true; profile.fabric.seed = kSeed;
  const std::string id = "dpol-cli-" + name;
  const EndpointExemption shared = EndpointExemption::SHARED_SOURCE_AND_DESTINATION;
  auto simple = [&](DiversityClass klass, EndpointExemption exemption, std::vector<DomainRelation> relations) {
    DiversityPolicy policy = synthetic_policy(id, default_scope(), SetSemantics::ALL_PAIRS, 2);
    policy.required_classes = {klass};
    policy.endpoint_exemption = exemption;
    policy.allowed_failure_domain_relations = std::move(relations);
    policy.description = "synthetic " + name + " profile";
    policy.canonicalize();
    return policy;
  };
  if (name == "link") { profile.policy = simple(DiversityClass::LINK_DISJOINT, EndpointExemption::NONE, {}); }
  else if (name == "transit-node") { profile.policy = simple(DiversityClass::TRANSIT_NODE_DISJOINT, shared, {}); }
  else if (name == "device") { profile.policy = simple(DiversityClass::DEVICE_DISJOINT, shared, {}); }
  else if (name == "failure-domain") {
    profile.policy = simple(DiversityClass::FAILURE_DOMAIN_DISJOINT, shared,
                            {DomainRelation::FAILURE_DOMAIN, DomainRelation::RACK, DomainRelation::POD, DomainRelation::SITE});
  } else if (name == "at-least-k") {
    profile.policy = synthetic_policy(id, default_scope(), SetSemantics::AT_LEAST_K_INDEPENDENT, 3);
    profile.fabric.spine_count = 3; profile.fabric.leaf_count = 8; profile.path_count = 8;
  } else if (name == "synthetic" || name == "incomplete") {
    profile.policy = synthetic_policy(id, default_scope(), SetSemantics::ALL_PAIRS, 2);
    profile.fabric.complete_domain_coverage = name != "incomplete";
  } else { return std::nullopt; }
  return profile;
}

// One synthetic evidence set, one publication authority and one runtime, with a registered
// publisher acting under the current coordinator epoch.
struct Scenario {
  explicit Scenario(const Limits& configured)
      : evidence(), publication(configured), runtime(evidence, evidence, evidence, publication, configured) {}
  ActingAuthority actor(const std::string& label) const {
    ActingAuthority authority;
    authority.epoch = publication.current_epoch(); authority.publisher = publisher; authority.boot = boot;
    authority.scope = default_scope(); authority.attempt = MutationAttemptId::parse("attempt-cli-" + label);
    return authority;
  }
  bool register_publisher(const std::string& label) {
    publisher = mint_publisher_id(label);
    boot = mint_worker_boot_id();
    PublisherSession session;
    session.publisher = publisher; session.boot = boot;
    session.epoch = publication.current_epoch(); session.scope = default_scope();
    return publication.register_publisher(session) == AuthorityStatus::ACCEPTED;
  }
  void feed(const SyntheticFabricOptions& options) {
    fabric = populate_synthetic_fabric(evidence, options);
    refs.clear();
    for (const SyntheticPath& entry : fabric.paths) { refs.push_back(PathRef{entry.path, entry.authority_generation}); }
  }
  InMemoryEvidence evidence;
  PublicationAuthority publication;
  DiversityRuntime runtime;
  SyntheticFabric fabric;
  std::vector<PathRef> refs;
  PublisherId publisher;
  WorkerBootId boot;
};
ProofRequest scenario_request(const Profile& profile, const std::vector<PathRef>& refs, DiversityPolicyGeneration generation) {
  ProofRequest request;
  request.policy = profile.policy.id; request.policy_generation = generation;
  const std::size_t count = refs.size() < profile.path_count ? refs.size() : profile.path_count;
  for (std::size_t index = 0; index < count; ++index) { request.paths.push_back(refs[index]); }
  request.canonicalize();
  return request;
}
void report_store(bool json, bool save, const std::string& path, PersistenceStatus status) {
  const std::string action = save ? "save" : "load";
  std::cout << (json ? jobj({"store", jtext(action), "path", jtext(path), "status", jenum(status)})
                     : action + " " + path + " status " + std::string(to_string(status))) << "\n";
}

// --- Rendering ---------------------------------------------------------------------------------
std::string conflicts_json(const std::vector<SharedResource>& conflicts) {
  Frag items;
  for (const SharedResource& conflict : conflicts) {
    Frag paths;
    for (std::uint32_t index : conflict.paths) { paths.push_back(jnum(index)); }
    items.push_back(jobj({"kind", jenum(conflict.kind), "relation", jenum(conflict.relation), "id", jtext(conflict.id), "paths", jarr(paths)}));
  }
  return jarr(items);
}
void print_proof(const DiversityProof& proof, bool json) {
  Frag paths;
  for (const PathRef& reference : proof.request.paths) { paths.push_back(jtext(reference.path.str())); }
  Frag classes;
  for (const ClassResult& result : proof.classes) {
    classes.push_back(jobj({"class", jenum(result.klass), "outcome", jenum(result.outcome), "evidence_complete",
                            jbool(result.evidence_complete), "shared_total", jnum(result.shared_total)}));
  }
  if (json) {
    const Frag witness = {"present", jbool(proof.witness.present), "requested_k", jnum(proof.witness.requested_k),
                          "achieved", jnum(proof.witness.achieved), "maximum_exact", jbool(proof.witness.maximum_exact)};
    std::cout << jobj({"command", jtext("evaluate"), "proof", jtext(proof.id.str()), "generation", jnum(proof.generation.value()),
                       "policy", jtext(proof.request.policy.str()), "outcome", jenum(proof.outcome), "lifecycle", jenum(proof.lifecycle),
                       "currentness", jenum(proof.currentness), "detail", jtext(proof.detail), "paths", jarr(paths), "classes", jarr(classes),
                       "conflicts", conflicts_json(proof.conflicts), "conflicts_total", jnum(proof.conflicts_total), "witness", jobj(witness),
                       "matrix_cells", jnum(proof.matrix.cells.size()), "request_digest", jtext(proof.request_digest.hex()),
                       "semantic_digest", jtext(proof.semantic_digest.hex())}) << "\n";
    return;
  }
  std::cout << "proof " << proof.id.str() << "@g" << proof.generation.value() << "\npolicy " << proof.request.policy.str()
            << "@g" << proof.request.policy_generation.value() << "\noutcome " << to_string(proof.outcome) << " lifecycle "
            << to_string(proof.lifecycle) << " currentness " << to_string(proof.currentness) << "\ndetail " << proof.detail
            << "\npaths [";
  for (std::size_t index = 0; index < proof.request.paths.size(); ++index) { std::cout << (index == 0 ? "" : ",") << proof.request.paths[index].path.str(); }
  std::cout << "]\nclasses";
  for (const ClassResult& result : proof.classes) {
    std::cout << " " << to_string(result.klass) << "=" << to_string(result.outcome) << "/"
              << (result.evidence_complete ? "COMPLETE" : "INCOMPLETE") << "/shared=" << result.shared_total;
  }
  std::cout << "\nconflicts " << proof.conflicts.size() << " of " << proof.conflicts_total << "\n";
  for (const SharedResource& conflict : proof.conflicts) { std::cout << "  " << conflict.render() << "\n"; }
  std::cout << "witness " << proof.witness.render() << "\nmatrix-cells " << proof.matrix.cells.size() << "\ndigest request "
            << proof.request_digest.hex() << "\ndigest semantic " << proof.semantic_digest.hex() << "\n";
}
void print_explanation(const Explanation& explanation, const std::string& policy) {
  Frag entries;
  for (const ExplanationEntry& entry : explanation.entries) {
    Frag paths;
    for (std::uint32_t index : entry.paths) { paths.push_back(jnum(index)); }
    entries.push_back(jobj({"kind", jenum(entry.kind), "class", jenum(entry.klass), "outcome", jenum(entry.outcome),
                            "subject", jtext(entry.subject), "detail", jtext(entry.detail), "paths", jarr(paths)}));
  }
  std::cout << jobj({"command", jtext("explain"), "policy", jtext(policy), "proof", jtext(explanation.proof.str()),
                     "generation", jnum(explanation.generation.value()), "outcome", jenum(explanation.outcome),
                     "truncated", jbool(explanation.truncated), "entries_total", jnum(explanation.entries_total),
                     "entries", jarr(entries)}) << "\n";
}

// --- Self test ---------------------------------------------------------------------------------
struct SelfTest {
  int failures = 0;
  int checks = 0;
  bool json = false;
  Frag cases;
  void check(const std::string& name, bool condition) {
    ++checks;
    failures += condition ? 0 : 1;
    cases.push_back(jobj({"name", jtext(name), "passed", jbool(condition)}));
    if (!json) { std::cout << (condition ? "PASS " : "FAIL ") << name << "\n"; }
  }
  void report() const {
    if (json) {
      std::cout << jobj({"command", jtext("selftest"), "checks", jnum(static_cast<std::uint64_t>(checks)), "failures",
                         jnum(static_cast<std::uint64_t>(failures)), "cases", jarr(cases)}) << "\n";
    } else { std::cout << "selftest checks=" << checks << " failures=" << failures << "\n"; }
  }
};
std::filesystem::path selftest_store_path() {
  const std::uint64_t ticks = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
  std::error_code error;
  std::filesystem::path root = std::filesystem::temp_directory_path(error);
  if (error) { root = std::filesystem::current_path(error); }
  return root / ("path_diversity-cli-selftest-" + std::to_string(ticks) + ".pdk");
}
int run_selftest(const Profile& profile, bool json) {
  SelfTest test;
  test.json = json;
  Limits limits;
  Scenario scenario(limits);
  scenario.feed(profile.fabric);
  test.check("publisher registered", scenario.register_publisher("cli-selftest"));
  const MutationResult published = scenario.runtime.publish_policy(profile.policy, scenario.actor("selftest-publish"));
  test.check("policy published", published.status == MutationStatus::APPLIED && published.has_policy);
  const ProofRequest request = scenario_request(profile, scenario.refs, scenario.runtime.policy_generation(profile.policy.id));
  test.check("request carries at least two paths", request.paths.size() >= 2);
  const MutationResult committed = scenario.runtime.evaluate(request, scenario.actor("selftest-evaluate"));
  test.check("proof committed", committed.status == MutationStatus::APPLIED && committed.has_proof);
  if (!committed.has_proof) { test.report(); return 1; }
  const DiversityProof& proof = committed.proof;
  test.check("outcome is a defined value", is_defined_proof_outcome(static_cast<std::uint8_t>(proof.outcome)));
  test.check("semantic digest is stable", proof_semantic_digest(proof) == proof.semantic_digest);
  test.check("identical re-evaluation does not advance",
             scenario.runtime.evaluate(request, scenario.actor("selftest-evaluate-again")).status == MutationStatus::UNCHANGED);
  bool named_result = false;
  const std::optional<Explanation> explanation = scenario.runtime.explain(proof.id);
  if (explanation.has_value()) {
    for (const ExplanationEntry& entry : explanation->entries) { named_result = named_result || entry.kind == ExplanationKind::PROOF_RESULT; }
  }
  test.check("explanation is present and names the result", explanation.has_value() && named_result);
  const std::optional<ProofSnapshot> snapshot = scenario.runtime.snapshot(proof.id);
  test.check("snapshot round trip is content addressed",
             snapshot.has_value() && snapshot_digest(*snapshot) == snapshot->digest && !scenario.runtime.snapshot_ids(proof.id).empty());
  test.check("reverse index finds the proof", scenario.runtime.proofs_for_path(request.paths[0].path).total >= 1);
  const std::filesystem::path store = selftest_store_path();
  const PersistenceStatus saved = scenario.runtime.save(store.string());
  test.check("store saved", saved == PersistenceStatus::OK);
  Scenario reloaded(limits);
  const bool loaded = saved == PersistenceStatus::OK && reloaded.runtime.load(store.string()) == PersistenceStatus::OK;
  test.check("store loaded", loaded);
  test.check("store round trip preserves proofs", loaded && reloaded.runtime.proof_count() == scenario.runtime.proof_count());
  test.check("store round trip preserves policies", loaded && reloaded.runtime.policy_count() == scenario.runtime.policy_count());
  std::error_code ignored;
  std::filesystem::remove(store, ignored);
  test.report();
  return test.failures == 0 ? 0 : 1;
}

// --- Inspection commands -----------------------------------------------------------------------
int run_inspection(Scenario& scenario, const Profile& profile, const Options& options) {
  std::optional<DiversityProofId> proof_id;
  if (options.load_path.empty()) {
    const MutationResult published = scenario.runtime.publish_policy(profile.policy, scenario.actor("publish"));
    if (!published.has_policy) { std::cerr << "path_diversity: policy publication failed: " << published.render() << "\n"; return 3; }
    const ProofRequest request = scenario_request(profile, scenario.refs, scenario.runtime.policy_generation(profile.policy.id));
    const MutationResult committed = scenario.runtime.evaluate(request, scenario.actor("evaluate"));
    if (!committed.has_proof) { std::cerr << "path_diversity: evaluation failed: " << committed.render() << "\n"; return 3; }
    proof_id = committed.proof.id;
  } else {
    const DiversityRuntime::QueryResult bound = scenario.runtime.proofs_for_policy(profile.policy.id);
    const DiversityRuntime::QueryResult all = scenario.runtime.all_proofs();
    if (!bound.proofs.empty()) { proof_id = bound.proofs.front(); }
    else if (!all.proofs.empty()) { proof_id = all.proofs.front(); }
  }
  if (options.command == "render") {
    if (!options.json) { std::cout << scenario.runtime.render(); return 0; }
    const RuntimeStats stats = scenario.runtime.stats();
    Frag proofs;
    for (const DiversityProofId& id : scenario.runtime.all_proofs().proofs) {
      const std::optional<DiversityProof> stored = scenario.runtime.proof(id);
      if (stored.has_value()) {
        proofs.push_back(jobj({"id", jtext(stored->id.str()), "generation", jnum(stored->generation.value()), "outcome",
                               jenum(stored->outcome), "lifecycle", jenum(stored->lifecycle), "currentness", jenum(stored->currentness)}));
      }
    }
    const Frag counters = {"evaluations", jnum(stats.evaluations), "commits", jnum(stats.commits), "unchanged_revalidations",
                           jnum(stats.unchanged_revalidations), "idempotent_replays", jnum(stats.idempotent_replays),
                           "rejected_mutations", jnum(stats.rejected_mutations), "watermark_rejections",
                           jnum(stats.watermark_rejections), "invalidations", jnum(stats.invalidations), "demotions", jnum(stats.demotions)};
    std::cout << jobj({"command", jtext("render"), "policy_count", jnum(scenario.runtime.policy_count()), "proof_count",
                       jnum(scenario.runtime.proof_count()), "stats", jobj(counters), "proofs", jarr(proofs)}) << "\n";
    return 0;
  }
  if (!proof_id.has_value()) { std::cerr << "path_diversity: no proof is available for " << options.command << "\n"; return 3; }
  if (options.command == "explain") {
    const std::optional<Explanation> explanation = scenario.runtime.explain(*proof_id);
    if (!explanation.has_value()) { std::cerr << "path_diversity: no proof is stored under " << proof_id->str() << "\n"; return 3; }
    if (options.json) { print_explanation(*explanation, profile.policy.id.str()); }
    else { std::cout << render_explanation(*explanation); }
    return 0;
  }
  const std::optional<DiversityProof> proof = scenario.runtime.proof(*proof_id);
  if (!proof.has_value()) { std::cerr << "path_diversity: no proof is stored under " << proof_id->str() << "\n"; return 3; }
  print_proof(*proof, options.json);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!parse_options(argc, argv, options)) { print_usage(std::cerr); return 2; }
  const bool known = options.command == "version" || options.command == "selftest" || options.command == "explain" ||
                     options.command == "evaluate" || options.command == "render";
  if (!known) {
    std::cerr << "path_diversity: unknown command " << options.command << "\n";
    print_usage(std::cerr);
    return 2;
  }
  const std::string profile_name = options.policy_name.empty() ? "synthetic" : options.policy_name;
  const std::optional<Profile> profile = profile_for(profile_name);
  if (!profile.has_value()) {
    std::cerr << "path_diversity: unknown policy name " << profile_name << "\n";
    print_usage(std::cerr);
    return 2;
  }
  if (options.command == "version" && options.pdk_path.empty() && options.load_path.empty()) { print_version(options.json); return 0; }
  Scenario scenario{Limits()};
  scenario.feed(profile->fabric);
  if (!options.load_path.empty()) {
    const PersistenceStatus loaded = scenario.runtime.load(options.load_path);
    report_store(options.json, false, options.load_path, loaded);
    if (loaded != PersistenceStatus::OK) {
      std::cerr << "path_diversity: refused store " << options.load_path << ": " << to_string(loaded) << "\n";
      return 3;
    }
  }
  // Registration happens after recovery: a restored coordinator epoch is the epoch a fresh
  // publisher session must bind.
  if (!scenario.register_publisher("cli")) { std::cerr << "path_diversity: publisher registration was refused\n"; return 3; }
  int status = 0;
  if (options.command == "version") { print_version(options.json); }
  else if (options.command == "selftest") { status = run_selftest(*profile, options.json); }
  else { status = run_inspection(scenario, *profile, options); }
  if (status != 0) { return status; }
  if (!options.pdk_path.empty()) {
    const PersistenceStatus saved = scenario.runtime.save(options.pdk_path);
    report_store(options.json, true, options.pdk_path, saved);
    if (saved != PersistenceStatus::OK) { std::cerr << "path_diversity: store was not written: " << to_string(saved) << "\n"; return 3; }
  }
  return 0;
}
