// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "path_diversity/authority.hpp"
#include "path_diversity/export.hpp"
#include "path_diversity/limits.hpp"
#include "path_diversity/mutation.hpp"
#include "path_diversity/runtime.hpp"
#include "path_diversity/wire.hpp"

namespace path_diversity {

// Loopback transport status. The distributed mode is a real TCP client/server
// pair; it is not a consensus protocol and it does not replicate between
// coordinators. One coordinator owns the registry.
enum class TransportStatus : std::uint8_t {
  OK = 1,
  NOT_STARTED = 2,
  ALREADY_STARTED = 3,
  BIND_FAILED = 4,
  LISTEN_FAILED = 5,
  CONNECT_FAILED = 6,
  IO_FAILURE = 7,
  CLOSED = 8,
  PROTOCOL_FAILURE = 9,
  // The peer disconnected while a request was outstanding. This is the signal
  // that drives worker-death detection.
  PEER_GONE = 10,
  UNAUTHORIZED = 11,
};

PATH_DIVERSITY_API std::string_view to_string(TransportStatus value) noexcept;

// Server side. Owns a listening socket on a loopback port and serves exactly one
// runtime.
class PATH_DIVERSITY_API DiversityCoordinator {
 public:
  DiversityCoordinator(DiversityRuntime& runtime, Limits limits = {});
  ~DiversityCoordinator();

  DiversityCoordinator(const DiversityCoordinator&) = delete;
  DiversityCoordinator& operator=(const DiversityCoordinator&) = delete;

  // Binds, listens and starts the accept loop on a background thread. Passing
  // port 0 selects an ephemeral port; port() reports the port actually bound.
  TransportStatus start(const std::string& address, std::uint16_t port);
  TransportStatus stop();
  bool running() const;
  std::uint16_t port() const;

  // Publisher sessions currently registered through this server.
  std::vector<PublisherSession> sessions() const;
  // Boots whose connection has been observed gone. Fencing is applied to the
  // runtime before the boot is reported here.
  std::vector<WorkerBootId> fenced_boots() const;
  // Bounded wait used by tests: true once at least the expected number of
  // connections has been accepted and every one of them has since gone away or
  // been fenced.
  bool wait_for_fenced_workers(std::uint32_t expected) const;

  // Durable store the coordinator keeps current. After every handled frame and
  // after every worker disconnect the store is written with atomic replacement,
  // so a hard kill never loses an acknowledged mutation.
  void set_store_path(std::string path);
  PersistenceStatus persist();

  std::uint64_t accepted_connections() const;
  std::uint64_t rejected_connections() const;
  std::string render() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Client side. A worker process presents a fresh WorkerBootId and publishes
// through the coordinator.
class PATH_DIVERSITY_API DiversityClient {
 public:
  explicit DiversityClient(Limits limits = {});
  ~DiversityClient();

  DiversityClient(const DiversityClient&) = delete;
  DiversityClient& operator=(const DiversityClient&) = delete;

  TransportStatus connect(const std::string& address, std::uint16_t port);
  TransportStatus close();
  bool connected() const;

  TransportStatus hello(const HelloPayload& payload);
  TransportStatus publish_policy(const ActingAuthority& authority, const DiversityPolicy& policy,
                                 MutationResult& out);
  TransportStatus publish_proof(const ActingAuthority& authority, const ProofRequest& request,
                                MutationResult& out);
  TransportStatus revalidate(const ActingAuthority& authority, const DiversityProofId& proof,
                             MutationResult& out);
  TransportStatus query(const QueryPayload& payload, QueryResultPayload& out);
  TransportStatus fence(const WorkerBootId& boot);
  TransportStatus ping();

  std::uint64_t round_trips() const;
  std::string render() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Deterministic rendering of a transport failure for diagnostics.
PATH_DIVERSITY_API std::string render_transport_status(TransportStatus status,
                                                       std::string_view detail);

}  // namespace path_diversity
