// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#include "path_diversity/distributed.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
// C6101 is raised inside ws2tcpip.h's inline getter stubs, which assign an
// _Out_ parameter on a path the analyzer cannot see. It is a finding in the
// platform header, not in first-party code, so the suppression is scoped to the
// include and lifted again immediately.
#pragma warning(push)
#pragma warning(disable : 6101)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma warning(pop)
using socket_handle = SOCKET;
constexpr socket_handle kInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_handle = int;
constexpr socket_handle kInvalidSocket = -1;
#endif

namespace path_diversity {

std::string_view to_string(TransportStatus value) noexcept {
  switch (value) {
    case TransportStatus::OK:
      return "OK";
    case TransportStatus::NOT_STARTED:
      return "NOT_STARTED";
    case TransportStatus::ALREADY_STARTED:
      return "ALREADY_STARTED";
    case TransportStatus::BIND_FAILED:
      return "BIND_FAILED";
    case TransportStatus::LISTEN_FAILED:
      return "LISTEN_FAILED";
    case TransportStatus::CONNECT_FAILED:
      return "CONNECT_FAILED";
    case TransportStatus::IO_FAILURE:
      return "IO_FAILURE";
    case TransportStatus::CLOSED:
      return "CLOSED";
    case TransportStatus::PROTOCOL_FAILURE:
      return "PROTOCOL_FAILURE";
    case TransportStatus::PEER_GONE:
      return "PEER_GONE";
    case TransportStatus::UNAUTHORIZED:
      return "UNAUTHORIZED";
  }
  return "UNKNOWN";
}

std::string render_transport_status(TransportStatus status, std::string_view detail) {
  std::string out(to_string(status));
  if (!detail.empty()) {
    out += ": ";
    out += detail;
  }
  return out;
}

namespace {

#if defined(_WIN32)
// Winsock initialisation can fail, and a transport that ignored that failure
// would go on to create sockets on an uninitialised stack. The result is
// recorded here and every caller refuses cleanly when it is false.
struct WinsockGuard {
  WinsockGuard() : ready(WSAStartup(MAKEWORD(2, 2), &data) == 0) {}
  ~WinsockGuard() {
    if (ready) {
      WSACleanup();
    }
  }
  WSADATA data{};
  bool ready = false;
};

bool ensure_winsock() {
  static WinsockGuard guard;
  return guard.ready;
}
#else
bool ensure_winsock() { return true; }
#endif

void close_socket(socket_handle handle) {
  if (handle == kInvalidSocket) {
    return;
  }
#if defined(_WIN32)
  closesocket(handle);
#else
  ::close(handle);
#endif
}

bool send_all(socket_handle handle, const std::uint8_t* data, std::size_t size) {
  std::size_t sent = 0;
  while (sent < size) {
    const int chunk = static_cast<int>(size - sent > 65536 ? 65536 : size - sent);
#if defined(_WIN32)
    const int written = ::send(handle, reinterpret_cast<const char*>(data + sent), chunk, 0);
#else
    const int written = static_cast<int>(::send(handle, data + sent, static_cast<std::size_t>(chunk), 0));
#endif
    if (written <= 0) {
      return false;
    }
    sent += static_cast<std::size_t>(written);
  }
  return true;
}

// Reads one chunk and appends it to the caller's buffer. The receive buffer is
// the caller's vector rather than a stack array: a per-connection thread stack
// must not carry a fixed sixteen-kilobyte frame buffer.
constexpr std::size_t kReceiveChunkBytes = 16384;

bool recv_some(socket_handle handle, std::vector<std::uint8_t>& buffer) {
  const std::size_t offset = buffer.size();
  buffer.resize(offset + kReceiveChunkBytes);
#if defined(_WIN32)
  const int read = ::recv(handle, reinterpret_cast<char*>(buffer.data() + offset),
                          static_cast<int>(kReceiveChunkBytes), 0);
#else
  const int read =
      static_cast<int>(::recv(handle, buffer.data() + offset, kReceiveChunkBytes, 0));
#endif
  if (read <= 0) {
    buffer.resize(offset);
    return false;
  }
  buffer.resize(offset + static_cast<std::size_t>(read));
  return true;
}

socket_handle connect_loopback(const std::string& address, std::uint16_t port) {
  if (!ensure_winsock()) {
    return kInvalidSocket;
  }
  socket_handle handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == kInvalidSocket) {
    return kInvalidSocket;
  }
  sockaddr_in target{};
  target.sin_family = AF_INET;
  target.sin_port = htons(port);
  if (::inet_pton(AF_INET, address.c_str(), &target.sin_addr) != 1) {
    close_socket(handle);
    return kInvalidSocket;
  }
  if (::connect(handle, reinterpret_cast<sockaddr*>(&target), sizeof(target)) != 0) {
    close_socket(handle);
    return kInvalidSocket;
  }
  return handle;
}

}  // namespace

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
struct DiversityCoordinator::Impl {
  Impl(DiversityRuntime& runtime_ref, Limits configured)
      : runtime(&runtime_ref), limits(configured) {}

  ~Impl() { stop(); }

  void stop() {
    bool expected = true;
    if (!running.compare_exchange_strong(expected, false)) {
      // still join below in case the loop is winding down
    }
    if (listen_socket != kInvalidSocket) {
      close_socket(listen_socket);
      listen_socket = kInvalidSocket;
    }
    if (accept_thread.joinable()) {
      accept_thread.join();
    }
    {
      std::lock_guard<std::mutex> guard(worker_mutex);
      for (socket_handle handle : worker_sockets) {
        close_socket(handle);
      }
      worker_sockets.clear();
    }
    for (std::thread& thread : worker_threads) {
      if (thread.joinable()) {
        thread.join();
      }
    }
    worker_threads.clear();
  }

  void serve(socket_handle handle) {
    FrameAssembler assembler(limits);
    std::vector<std::uint8_t> buffer;
    buffer.reserve(kReceiveChunkBytes);
    WorkerBootId boot;
    bool have_boot = false;
    while (running.load()) {
      buffer.clear();
      if (!recv_some(handle, buffer)) {
        break;
      }
      assembler.append(buffer.data(), buffer.size());
      WireFrame frame;
      while (assembler.next(frame) == WireStatus::OK) {
        handle_frame(handle, frame, boot, have_boot);
      }
      if (assembler.status() != WireStatus::OK) {
        break;
      }
    }
    if (have_boot) {
      // The worker is gone. Fencing is permanent, and every live publication
      // attributed to that boot loses its live authority immediately.
      publication_fence(boot);
      persist();
    }
    close_socket(handle);
    {
      std::lock_guard<std::mutex> guard(worker_mutex);
      worker_sockets.erase(
          std::remove(worker_sockets.begin(), worker_sockets.end(), handle),
          worker_sockets.end());
      ++finished_workers;
    }
    worker_signal.notify_all();
  }

  void publication_fence(const WorkerBootId& boot) {
    {
      std::lock_guard<std::mutex> guard(worker_mutex);
      fenced_boot_list.push_back(boot);
    }
    // Fencing is permanent and is applied in the publication authority;
    // demoting the publications of the fenced boot is applied in the runtime.
    runtime->fence_boot(boot);
  }

  void persist() {
    std::string path;
    {
      std::lock_guard<std::mutex> guard(worker_mutex);
      path = store_path;
    }
    if (!path.empty()) {
      runtime->save(path);
    }
  }

  void handle_frame(socket_handle handle, const WireFrame& frame, WorkerBootId& boot,
                    bool& have_boot) {
    ByteReader reader(frame.payload.data(), frame.payload.size());
    switch (frame.message) {
      case MessageId::HELLO: {
        HelloPayload hello;
        if (decode_hello(reader, limits, hello) != DecodeStatus::OK || !reader.at_end()) {
          send_error(handle, WireStatus::MALFORMED_PAYLOAD, "malformed HELLO");
          return;
        }
        boot = hello.boot;
        have_boot = true;
        PublisherSession session{hello.publisher, hello.boot, hello.epoch, hello.scope, false};
        const AuthorityStatus registered = runtime->register_publisher(session);
        {
          std::lock_guard<std::mutex> guard(session_mutex);
          session.fenced = registered != AuthorityStatus::ACCEPTED;
          session_list.push_back(session);
        }
        if (registered != AuthorityStatus::ACCEPTED) {
          send_error(handle, WireStatus::MALFORMED_PAYLOAD,
                     std::string("publisher registration refused: ") +
                         std::string(to_string(registered)));
          return;
        }
        send_message(handle, MessageId::HELLO_ACK, std::vector<std::uint8_t>());
        return;
      }
      case MessageId::PUBLISH_POLICY: {
        PublishPolicyPayload payload;
        if (decode_publish_policy(reader, limits, payload) != DecodeStatus::OK || !reader.at_end()) {
          send_error(handle, WireStatus::MALFORMED_PAYLOAD, "malformed PUBLISH_POLICY");
          return;
        }
        const MutationResult result = runtime->publish_policy(payload.policy, payload.authority);
        // Durable before acknowledged.
        persist();
        send_mutation(handle, result);
        return;
      }
      case MessageId::PUBLISH_PROOF: {
        PublishProofPayload payload;
        if (decode_publish_proof(reader, limits, payload) != DecodeStatus::OK || !reader.at_end()) {
          send_error(handle, WireStatus::MALFORMED_PAYLOAD, "malformed PUBLISH_PROOF");
          return;
        }
        const MutationResult result = runtime->evaluate(payload.request, payload.authority);
        // Durable before acknowledged.
        persist();
        send_mutation(handle, result);
        return;
      }
      case MessageId::REVALIDATE: {
        RevalidatePayload payload;
        if (decode_revalidate(reader, limits, payload) != DecodeStatus::OK || !reader.at_end()) {
          send_error(handle, WireStatus::MALFORMED_PAYLOAD, "malformed REVALIDATE");
          return;
        }
        const MutationResult result = runtime->revalidate(payload.proof, payload.authority);
        // Durable before acknowledged.
        persist();
        send_mutation(handle, result);
        return;
      }
      case MessageId::QUERY: {
        QueryPayload payload;
        if (decode_query(reader, limits, payload) != DecodeStatus::OK || !reader.at_end()) {
          send_error(handle, WireStatus::MALFORMED_PAYLOAD, "malformed QUERY");
          return;
        }
        DiversityRuntime::QueryResult result;
        switch (payload.selector) {
          case 1:
            result = runtime->proofs_for_path(payload.path);
            break;
          case 2:
            result = runtime->proofs_for_domain(payload.domain);
            break;
          case 3:
            result = runtime->proofs_for_policy(payload.policy);
            break;
          case 4:
            result = runtime->proofs_for_entity(EntityRef{payload.entity_kind, payload.entity_id});
            break;
          case 5:
            result = runtime->current_proofs();
            break;
          default:
            result = runtime->all_proofs();
            break;
        }
        QueryResultPayload reply;
        reply.proofs = std::move(result.proofs);
        reply.truncated = result.truncated;
        reply.total = result.total;
        ByteWriter writer;
        encode_query_result(writer, reply);
        send_message(handle, MessageId::QUERY_RESULT, writer.take());
        return;
      }
      case MessageId::FENCE: {
        std::string text;
        if (!reader.text(text, limits.max_identity_length) || !reader.at_end()) {
          send_error(handle, WireStatus::MALFORMED_PAYLOAD, "malformed FENCE");
          return;
        }
        const auto parsed = WorkerBootId::from_wire(text);
        if (!parsed.has_value()) {
          send_error(handle, WireStatus::MALFORMED_PAYLOAD, "malformed FENCE identity");
          return;
        }
        publication_fence(*parsed);
        send_message(handle, MessageId::PONG, std::vector<std::uint8_t>());
        return;
      }
      case MessageId::PING:
        send_message(handle, MessageId::PONG, std::vector<std::uint8_t>());
        return;
      case MessageId::CLOSE:
        return;
      default:
        send_error(handle, WireStatus::UNKNOWN_MESSAGE, "message is not accepted by this server");
        return;
    }
  }

  void send_error(socket_handle handle, WireStatus status, const std::string& detail) {
    ByteWriter writer;
    ErrorPayload payload;
    payload.status = status;
    payload.detail = detail;
    encode_error(writer, payload);
    send_message(handle, MessageId::ERROR_REPLY, writer.take());
  }

  void send_mutation(socket_handle handle, const MutationResult& result) {
    MutationResultPayload payload;
    payload.status = result.status;
    payload.detail = result.detail;
    payload.has_proof = result.has_proof;
    if (result.has_proof) {
      payload.proof = result.proof;
    }
    ByteWriter writer;
    encode_mutation_result(writer, payload);
    send_message(handle, MessageId::PUBLISH_PROOF, writer.take());
  }

  void send_message(socket_handle handle, MessageId message, std::vector<std::uint8_t> payload) {
    const std::vector<std::uint8_t> bytes = encode_frame(message, payload, limits);
    if (bytes.empty()) {
      return;
    }
    std::lock_guard<std::mutex> guard(write_mutex);
    send_all(handle, bytes.data(), bytes.size());
  }

  DiversityRuntime* runtime;
  Limits limits;
  std::string store_path;
  socket_handle listen_socket = kInvalidSocket;
  std::atomic<bool> running{false};
  std::thread accept_thread;
  std::vector<std::thread> worker_threads;
  std::vector<socket_handle> worker_sockets;
  mutable std::mutex worker_mutex;
  mutable std::mutex write_mutex;
  mutable std::mutex session_mutex;
  mutable std::mutex signal_mutex;
  mutable std::condition_variable worker_signal;
  std::vector<PublisherSession> session_list;
  std::vector<WorkerBootId> fenced_boot_list;
  std::uint64_t finished_workers = 0;
  std::atomic<std::uint64_t> accepted{0};
  std::atomic<std::uint64_t> rejected{0};
  std::uint16_t bound_port = 0;
};

DiversityCoordinator::DiversityCoordinator(DiversityRuntime& runtime, Limits limits)
    : impl_(new Impl(runtime, limits)) {}

DiversityCoordinator::~DiversityCoordinator() = default;

TransportStatus DiversityCoordinator::start(const std::string& address, std::uint16_t port) {
  if (impl_->running.load()) {
    return TransportStatus::ALREADY_STARTED;
  }
  if (!ensure_winsock()) {
    return TransportStatus::BIND_FAILED;
  }
  socket_handle handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == kInvalidSocket) {
    return TransportStatus::BIND_FAILED;
  }
  int reuse = 1;
  ::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
               sizeof(reuse));
  sockaddr_in local{};
  local.sin_family = AF_INET;
  local.sin_port = htons(port);
  if (::inet_pton(AF_INET, address.c_str(), &local.sin_addr) != 1) {
    close_socket(handle);
    return TransportStatus::BIND_FAILED;
  }
  if (::bind(handle, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
    close_socket(handle);
    return TransportStatus::BIND_FAILED;
  }
  if (::listen(handle, 8) != 0) {
    close_socket(handle);
    return TransportStatus::LISTEN_FAILED;
  }
  sockaddr_in actual{};
#if defined(_WIN32)
  int actual_size = sizeof(actual);
#else
  socklen_t actual_size = sizeof(actual);
#endif
  if (::getsockname(handle, reinterpret_cast<sockaddr*>(&actual), &actual_size) == 0) {
    impl_->bound_port = ntohs(actual.sin_port);
  } else {
    impl_->bound_port = port;
  }
  impl_->listen_socket = handle;
  impl_->running.store(true);
  impl_->accept_thread = std::thread([this]() {
    while (impl_->running.load()) {
      sockaddr_in remote{};
#if defined(_WIN32)
      int remote_size = sizeof(remote);
#else
      socklen_t remote_size = sizeof(remote);
#endif
      socket_handle client =
          ::accept(impl_->listen_socket, reinterpret_cast<sockaddr*>(&remote), &remote_size);
      if (client == kInvalidSocket) {
        if (!impl_->running.load()) {
          break;
        }
        continue;
      }
      {
        std::lock_guard<std::mutex> guard(impl_->worker_mutex);
        if (impl_->worker_sockets.size() >= impl_->limits.max_publishers) {
          ++impl_->rejected;
          close_socket(client);
          continue;
        }
        impl_->worker_sockets.push_back(client);
      }
      ++impl_->accepted;
      impl_->worker_threads.emplace_back([this, client]() { impl_->serve(client); });
    }
  });

  return TransportStatus::OK;
}

TransportStatus DiversityCoordinator::stop() {
  impl_->stop();
  return TransportStatus::OK;
}

bool DiversityCoordinator::running() const { return impl_->running.load(); }

std::uint16_t DiversityCoordinator::port() const { return impl_->bound_port; }

std::vector<PublisherSession> DiversityCoordinator::sessions() const {
  std::lock_guard<std::mutex> guard(impl_->session_mutex);
  return impl_->session_list;
}

std::vector<WorkerBootId> DiversityCoordinator::fenced_boots() const {
  std::lock_guard<std::mutex> guard(impl_->worker_mutex);
  return impl_->fenced_boot_list;
}

bool DiversityCoordinator::wait_for_fenced_workers(std::uint32_t expected) const {
  // A bounded wait whose crossing is an explicit failure of the caller.
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  std::unique_lock<std::mutex> lock(impl_->signal_mutex);
  while (true) {
    {
      std::lock_guard<std::mutex> worker_guard(impl_->worker_mutex);
      if (impl_->fenced_boot_list.size() >= expected && impl_->finished_workers >= expected) {
        return true;
      }
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      return false;
    }
    impl_->worker_signal.wait_for(lock, std::chrono::milliseconds(20));
  }
}

void DiversityCoordinator::set_store_path(std::string path) {
  std::lock_guard<std::mutex> guard(impl_->worker_mutex);
  impl_->store_path = std::move(path);
}

PersistenceStatus DiversityCoordinator::persist() {
  impl_->persist();
  return PersistenceStatus::OK;
}

std::uint64_t DiversityCoordinator::accepted_connections() const { return impl_->accepted.load(); }

std::uint64_t DiversityCoordinator::rejected_connections() const { return impl_->rejected.load(); }

std::string DiversityCoordinator::render() const {
  std::string out = "coordinator port=" + std::to_string(impl_->bound_port);
  out += impl_->running.load() ? " running" : " stopped";
  out += " accepted=" + std::to_string(impl_->accepted.load());
  out += " rejected=" + std::to_string(impl_->rejected.load());
  out += " fenced=" + std::to_string(impl_->fenced_boot_list.size());
  return out;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------
struct DiversityClient::Impl {
  explicit Impl(Limits configured) : limits(configured) {}

  ~Impl() { close(); }

  void close() {
    if (socket != kInvalidSocket) {
      close_socket(socket);
      socket = kInvalidSocket;
    }
    if (assembler) {
      assembler->clear();
    }
    round_trips.store(0);
  }

  bool request(MessageId message, const std::vector<std::uint8_t>& payload, WireFrame& reply) {
    if (socket == kInvalidSocket) {
      return false;
    }
    const std::vector<std::uint8_t> bytes = encode_frame(message, payload, limits);
    if (bytes.empty()) {
      return false;
    }
    if (!send_all(socket, bytes.data(), bytes.size())) {
      return false;
    }
    while (true) {
      if (assembler->next(reply) == WireStatus::OK) {
        ++round_trips;
        return true;
      }
      if (assembler->status() != WireStatus::OK) {
        return false;
      }
      if (!recv_some(socket, scratch)) {
        return false;
      }
      assembler->append(scratch.data(), scratch.size());
      scratch.clear();
    }
  }

  Limits limits;
  socket_handle socket = kInvalidSocket;
  std::unique_ptr<FrameAssembler> assembler;
  std::vector<std::uint8_t> scratch;
  std::atomic<std::uint64_t> round_trips{0};
  std::mutex mutex;
};

DiversityClient::DiversityClient(Limits limits) : impl_(new Impl(limits)) {
  impl_->assembler.reset(new FrameAssembler(limits));
}

DiversityClient::~DiversityClient() = default;

TransportStatus DiversityClient::connect(const std::string& address, std::uint16_t port) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  impl_->close();
  impl_->socket = connect_loopback(address, port);
  if (impl_->socket == kInvalidSocket) {
    return TransportStatus::CONNECT_FAILED;
  }
  return TransportStatus::OK;
}

TransportStatus DiversityClient::close() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  impl_->close();
  return TransportStatus::OK;
}

bool DiversityClient::connected() const { return impl_->socket != kInvalidSocket; }

TransportStatus DiversityClient::hello(const HelloPayload& payload) {
  ByteWriter writer;
  encode_hello(writer, payload);
  WireFrame reply;
  if (!impl_->request(MessageId::HELLO, writer.take(), reply)) {
    return TransportStatus::PEER_GONE;
  }
  if (reply.message != MessageId::HELLO_ACK) {
    return TransportStatus::PROTOCOL_FAILURE;
  }
  return TransportStatus::OK;
}

namespace {

TransportStatus decode_mutation_reply(const Limits& limits, const WireFrame& reply,
                                      MutationResult& out) {
  if (reply.message == MessageId::ERROR_REPLY) {
    return TransportStatus::PROTOCOL_FAILURE;
  }
  ByteReader reader(reply.payload.data(), reply.payload.size());
  MutationResultPayload payload;
  if (decode_mutation_result(reader, limits, payload) != DecodeStatus::OK || !reader.at_end()) {
    return TransportStatus::PROTOCOL_FAILURE;
  }
  out.status = payload.status;
  out.detail = payload.detail;
  out.has_proof = payload.has_proof;
  if (payload.has_proof) {
    out.proof = payload.proof;
  }
  return TransportStatus::OK;
}

}  // namespace

TransportStatus DiversityClient::publish_policy(const ActingAuthority& authority,
                                                const DiversityPolicy& policy,
                                                MutationResult& out) {
  ByteWriter writer;
  PublishPolicyPayload payload;
  payload.authority = authority;
  payload.policy = policy;
  encode_publish_policy(writer, payload);
  WireFrame reply;
  if (!impl_->request(MessageId::PUBLISH_POLICY, writer.take(), reply)) {
    return TransportStatus::PEER_GONE;
  }
  return decode_mutation_reply(impl_->limits, reply, out);
}

TransportStatus DiversityClient::publish_proof(const ActingAuthority& authority,
                                               const ProofRequest& request, MutationResult& out) {
  ByteWriter writer;
  PublishProofPayload payload;
  payload.authority = authority;
  payload.request = request;
  encode_publish_proof(writer, payload);
  WireFrame reply;
  if (!impl_->request(MessageId::PUBLISH_PROOF, writer.take(), reply)) {
    return TransportStatus::PEER_GONE;
  }
  return decode_mutation_reply(impl_->limits, reply, out);
}

TransportStatus DiversityClient::revalidate(const ActingAuthority& authority,
                                            const DiversityProofId& proof, MutationResult& out) {
  ByteWriter writer;
  RevalidatePayload payload;
  payload.authority = authority;
  payload.proof = proof;
  encode_revalidate(writer, payload);
  WireFrame reply;
  if (!impl_->request(MessageId::REVALIDATE, writer.take(), reply)) {
    return TransportStatus::PEER_GONE;
  }
  return decode_mutation_reply(impl_->limits, reply, out);
}

TransportStatus DiversityClient::query(const QueryPayload& payload, QueryResultPayload& out) {
  ByteWriter writer;
  encode_query(writer, payload);
  WireFrame reply;
  if (!impl_->request(MessageId::QUERY, writer.take(), reply)) {
    return TransportStatus::PEER_GONE;
  }
  if (reply.message != MessageId::QUERY_RESULT) {
    return TransportStatus::PROTOCOL_FAILURE;
  }
  ByteReader reader(reply.payload.data(), reply.payload.size());
  if (decode_query_result(reader, impl_->limits, out) != DecodeStatus::OK || !reader.at_end()) {
    return TransportStatus::PROTOCOL_FAILURE;
  }
  return TransportStatus::OK;
}

TransportStatus DiversityClient::fence(const WorkerBootId& boot) {
  ByteWriter writer;
  writer.text(boot.view());
  WireFrame reply;
  if (!impl_->request(MessageId::FENCE, writer.take(), reply)) {
    return TransportStatus::PEER_GONE;
  }
  return reply.message == MessageId::PONG ? TransportStatus::OK
                                          : TransportStatus::PROTOCOL_FAILURE;
}

TransportStatus DiversityClient::ping() {
  WireFrame reply;
  if (!impl_->request(MessageId::PING, std::vector<std::uint8_t>(), reply)) {
    return TransportStatus::PEER_GONE;
  }
  return reply.message == MessageId::PONG ? TransportStatus::OK
                                          : TransportStatus::PROTOCOL_FAILURE;
}

std::uint64_t DiversityClient::round_trips() const { return impl_->round_trips.load(); }

std::string DiversityClient::render() const {
  std::string out = "client ";
  out += impl_->socket == kInvalidSocket ? "disconnected" : "connected";
  out += " round-trips=" + std::to_string(impl_->round_trips.load());
  return out;
}

}  // namespace path_diversity
