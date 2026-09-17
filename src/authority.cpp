// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/authority.hpp"

#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <random>
#include <string>
#include <utility>

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#else
#include <unistd.h>
#endif

namespace path_diversity {

std::string_view to_string(AuthorityStatus value) noexcept {
  switch (value) {
    case AuthorityStatus::ACCEPTED:
      return "ACCEPTED";
    case AuthorityStatus::IDEMPOTENT:
      return "IDEMPOTENT";
    case AuthorityStatus::UNAUTHORIZED:
      return "UNAUTHORIZED";
    case AuthorityStatus::FENCED_PUBLISHER:
      return "FENCED_PUBLISHER";
    case AuthorityStatus::STALE_EPOCH:
      return "STALE_EPOCH";
    case AuthorityStatus::SCOPE_MISMATCH:
      return "SCOPE_MISMATCH";
    case AuthorityStatus::GENERATION_CONFLICT:
      return "GENERATION_CONFLICT";
    case AuthorityStatus::ATTEMPT_CONFLICT:
      return "ATTEMPT_CONFLICT";
    case AuthorityStatus::LIMIT_EXCEEDED:
      return "LIMIT_EXCEEDED";
    case AuthorityStatus::MALFORMED:
      return "MALFORMED";
  }
  return "UNKNOWN";
}

bool is_defined_authority_status(std::uint8_t raw) noexcept {
  return raw >= static_cast<std::uint8_t>(AuthorityStatus::ACCEPTED) &&
         raw <= static_cast<std::uint8_t>(AuthorityStatus::MALFORMED);
}

bool authority_status_is_success(AuthorityStatus value) noexcept {
  return value == AuthorityStatus::ACCEPTED || value == AuthorityStatus::IDEMPOTENT;
}

bool authority_status_needs_demotion(AuthorityStatus value) noexcept {
  return value == AuthorityStatus::FENCED_PUBLISHER || value == AuthorityStatus::STALE_EPOCH ||
         value == AuthorityStatus::UNAUTHORIZED || value == AuthorityStatus::SCOPE_MISMATCH;
}

std::string PublisherSession::render() const {
  std::string out = "publisher ";
  out += publisher.str();
  out += " boot=";
  out += boot.str();
  out += " epoch=g";
  out += std::to_string(epoch.value());
  out += " scope=";
  out += scope.str();
  out += fenced ? " FENCED" : " live";
  return out;
}

struct PublicationAuthority::Impl {
  explicit Impl(const Limits& configured) : limits(configured) {}

  mutable std::mutex mutex;
  Limits limits;
  CoordinatorEpoch epoch = CoordinatorEpoch::from_value(1);
  bool epoch_restored = false;
  std::map<WorkerBootId, PublisherSession> sessions;
  std::map<WorkerBootId, bool> fenced;
  std::map<MutationAttemptId, std::pair<Digest, DiversityProofId>> attempts;
};

PublicationAuthority::PublicationAuthority(const Limits& limits) : impl_(new Impl(limits)) {}

PublicationAuthority::~PublicationAuthority() = default;

AuthorityStatus PublicationAuthority::restore_epoch(CoordinatorEpoch epoch) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!epoch.is_set()) {
    return AuthorityStatus::MALFORMED;
  }
  if (impl_->epoch_restored && epoch < impl_->epoch) {
    // Epochs never move backwards; a coordinator that restarts always comes
    // back strictly higher.
    return AuthorityStatus::STALE_EPOCH;
  }
  impl_->epoch = epoch;
  impl_->epoch_restored = true;
  return AuthorityStatus::ACCEPTED;
}

CoordinatorEpoch PublicationAuthority::current_epoch() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->epoch;
}

AuthorityStatus PublicationAuthority::register_publisher(const PublisherSession& session) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!session.publisher.valid() || !session.boot.valid() || !session.scope.valid() ||
      !session.epoch.is_set()) {
    return AuthorityStatus::MALFORMED;
  }
  const auto fenced = impl_->fenced.find(session.boot);
  if (fenced != impl_->fenced.end() && fenced->second) {
    return AuthorityStatus::FENCED_PUBLISHER;
  }
  if (session.epoch != impl_->epoch) {
    return AuthorityStatus::STALE_EPOCH;
  }
  // A publisher registering a new boot permanently fences the boot it replaces.
  for (auto& entry : impl_->sessions) {
    if (entry.second.publisher == session.publisher && !(entry.first == session.boot)) {
      entry.second.fenced = true;
      impl_->fenced[entry.first] = true;
    }
  }
  if (impl_->sessions.find(session.boot) == impl_->sessions.end() &&
      impl_->sessions.size() >= impl_->limits.max_publishers) {
    return AuthorityStatus::LIMIT_EXCEEDED;
  }
  PublisherSession stored = session;
  stored.fenced = false;
  impl_->sessions[session.boot] = stored;
  impl_->fenced[session.boot] = false;
  return AuthorityStatus::ACCEPTED;
}

AuthorityStatus PublicationAuthority::fence_boot(const WorkerBootId& boot) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!boot.valid()) {
    return AuthorityStatus::MALFORMED;
  }
  // Fencing is permanent: a fenced boot never becomes live again, in this
  // process or after a restart that recovered the fence list.
  impl_->fenced[boot] = true;
  const auto found = impl_->sessions.find(boot);
  if (found != impl_->sessions.end()) {
    found->second.fenced = true;
  }
  return AuthorityStatus::ACCEPTED;
}

bool PublicationAuthority::is_fenced(const WorkerBootId& boot) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const auto found = impl_->fenced.find(boot);
  return found != impl_->fenced.end() && found->second;
}

AuthorityStatus PublicationAuthority::validate(const ActingAuthority& authority) const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  if (!authority.publisher.valid() || !authority.boot.valid() || !authority.scope.valid() ||
      !authority.attempt.valid() || !authority.epoch.is_set()) {
    return AuthorityStatus::MALFORMED;
  }
  const auto fenced = impl_->fenced.find(authority.boot);
  if (fenced != impl_->fenced.end() && fenced->second) {
    return AuthorityStatus::FENCED_PUBLISHER;
  }
  if (authority.epoch != impl_->epoch) {
    return AuthorityStatus::STALE_EPOCH;
  }
  const auto session = impl_->sessions.find(authority.boot);
  if (session == impl_->sessions.end()) {
    // Connected is not authorized.
    return AuthorityStatus::UNAUTHORIZED;
  }
  if (session->second.fenced) {
    return AuthorityStatus::FENCED_PUBLISHER;
  }
  if (!(session->second.publisher == authority.publisher)) {
    return AuthorityStatus::UNAUTHORIZED;
  }
  if (!(session->second.scope == authority.scope)) {
    return AuthorityStatus::SCOPE_MISMATCH;
  }
  return AuthorityStatus::ACCEPTED;
}

AuthorityStatus PublicationAuthority::admit(const ActingAuthority& authority,
                                            const Digest& payload_digest) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const AuthorityStatus validated = [&]() {
    if (!authority.publisher.valid() || !authority.boot.valid() || !authority.scope.valid() ||
        !authority.attempt.valid() || !authority.epoch.is_set()) {
      return AuthorityStatus::MALFORMED;
    }
    const auto fenced = impl_->fenced.find(authority.boot);
    if (fenced != impl_->fenced.end() && fenced->second) {
      return AuthorityStatus::FENCED_PUBLISHER;
    }
    if (authority.epoch != impl_->epoch) {
      return AuthorityStatus::STALE_EPOCH;
    }
    const auto session = impl_->sessions.find(authority.boot);
    if (session == impl_->sessions.end() || session->second.fenced) {
      return session == impl_->sessions.end() ? AuthorityStatus::UNAUTHORIZED
                                              : AuthorityStatus::FENCED_PUBLISHER;
    }
    if (!(session->second.publisher == authority.publisher)) {
      return AuthorityStatus::UNAUTHORIZED;
    }
    if (!(session->second.scope == authority.scope)) {
      return AuthorityStatus::SCOPE_MISMATCH;
    }
    return AuthorityStatus::ACCEPTED;
  }();
  if (validated != AuthorityStatus::ACCEPTED) {
    return validated;
  }
  const auto existing = impl_->attempts.find(authority.attempt);
  if (existing != impl_->attempts.end()) {
    if (existing->second.first == payload_digest) {
      return AuthorityStatus::IDEMPOTENT;
    }
    return AuthorityStatus::ATTEMPT_CONFLICT;
  }
  if (impl_->attempts.size() >= impl_->limits.max_attempts_tracked) {
    return AuthorityStatus::LIMIT_EXCEEDED;
  }
  impl_->attempts[authority.attempt] = std::make_pair(payload_digest, DiversityProofId());
  return AuthorityStatus::ACCEPTED;
}

void PublicationAuthority::forget_attempt(const MutationAttemptId& attempt) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  impl_->attempts.erase(attempt);
}

std::vector<WorkerBootId> PublicationAuthority::fenced_boots() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<WorkerBootId> out;
  for (const auto& entry : impl_->fenced) {
    if (entry.second) {
      out.push_back(entry.first);
    }
  }
  return out;
}

std::size_t PublicationAuthority::session_count() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->sessions.size();
}

std::string PublicationAuthority::render() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::string out = "authority epoch=g";
  out += std::to_string(impl_->epoch.value());
  out += " sessions=" + std::to_string(impl_->sessions.size());
  out += " attempts=" + std::to_string(impl_->attempts.size());
  out += " fenced=" + std::to_string(impl_->fenced.size());
  out += "\n";
  for (const auto& entry : impl_->sessions) {
    out += "  ";
    out += entry.second.render();
    out += "\n";
  }
  return out;
}

// ---------------------------------------------------------------------------
// Process identity mints.
// ---------------------------------------------------------------------------
namespace {

std::uint64_t process_salt() {
  static const std::uint64_t salt = []() {
    std::random_device device;
    std::uint64_t value = (static_cast<std::uint64_t>(device()) << 32) ^
                          static_cast<std::uint64_t>(device());
    const auto ticks = static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    value ^= ticks;
#if defined(_WIN32)
    value ^= static_cast<std::uint64_t>(_getpid()) << 40;
#else
    value ^= static_cast<std::uint64_t>(getpid()) << 40;
#endif
    return value;
  }();
  return salt;
}

std::uint64_t next_serial() {
  static std::atomic<std::uint64_t> counter{0};
  return counter.fetch_add(1, std::memory_order_relaxed) + 1;
}

std::string hex16(std::uint64_t value) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.reserve(16);
  for (int i = 15; i >= 0; --i) {
    out.push_back(digits[(value >> (4 * i)) & 0x0fULL]);
  }
  return out;
}

}  // namespace

WorkerBootId mint_worker_boot_id() {
  static const std::uint64_t salt = process_salt();
  const std::uint64_t serial = next_serial();
  const std::uint64_t mix = salt ^ (serial * 0x9e3779b97f4a7c15ULL);
  return WorkerBootId::parse("boot-" + hex16(mix));
}

PublisherId mint_publisher_id(std::string_view label) {
  std::string text = "pub-";
  text += label.empty() ? std::string("anonymous") : std::string(label);
  const std::uint64_t mix = process_salt() ^ (next_serial() * 0xbf58476d1ce4e5b9ULL);
  text += "-";
  text += hex16(mix).substr(0, 8);
  if (!PublisherId::try_parse(text).has_value()) {
    return PublisherId::parse("pub-anonymous");
  }
  return PublisherId::parse(text);
}

MutationAttemptId mint_mutation_attempt_id() {
  const std::uint64_t mix = process_salt() ^ (next_serial() * 0x94d049bb133111ebULL);
  return MutationAttemptId::parse("attempt-" + hex16(mix));
}

}  // namespace path_diversity
