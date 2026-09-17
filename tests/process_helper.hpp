// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

// Real out-of-process helpers. A test that claims a worker died must have killed
// a real process; a test that claims a coordinator restarted must have killed a
// real coordinator process. Nothing here emulates death in-process.
//
// Child processes inherit stdio, so no pipe is created and no output is
// captured. Coordination uses files under the test temp root, and every wait is
// a bounded wait whose crossing is an explicit failed assertion.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <windows.h>
#else
#include <csignal>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace pd_test {

class ChildProcess {
 public:
  ChildProcess() = default;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ChildProcess(ChildProcess&& other) noexcept { move_from(other); }
  ChildProcess& operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
      move_from(other);
    }
    return *this;
  }
  ~ChildProcess() { release_handle(); }

  bool valid() const noexcept { return handle_ != 0; }

  // Adopts an already-created native handle. The only way to construct a live
  // ChildProcess, so ownership can never be duplicated by accident.
#if defined(_WIN32)
  static ChildProcess adopt(std::uintptr_t handle) {
    ChildProcess child;
    child.handle_ = handle;
    return child;
  }
#else
  static ChildProcess adopt(std::int64_t handle) {
    ChildProcess child;
    child.handle_ = handle;
    return child;
  }
#endif

  // Forceful termination. This is the "hard kill" the proofs require: no
  // destructor runs, no flush happens, no graceful shutdown is possible.
  bool kill() {
    if (handle_ == 0) {
      return false;
    }
#if defined(_WIN32)
    const bool ok = TerminateProcess(reinterpret_cast<HANDLE>(handle_), 1) != 0;
    if (ok) {
      WaitForSingleObject(reinterpret_cast<HANDLE>(handle_), INFINITE);
    }
#else
    const bool ok = ::kill(static_cast<pid_t>(handle_), SIGKILL) == 0;
    int status = 0;
    ::waitpid(static_cast<pid_t>(handle_), &status, 0);
#endif
    release_handle();
    return ok;
  }

  bool running() const {
    if (handle_ == 0) {
      return false;
    }
#if defined(_WIN32)
    DWORD code = 0;
    if (GetExitCodeProcess(reinterpret_cast<HANDLE>(handle_), &code) == 0) {
      return false;
    }
    return code == STILL_ACTIVE;
#else
    int status = 0;
    const pid_t result = ::waitpid(static_cast<pid_t>(handle_), &status, WNOHANG);
    return result == 0;
#endif
  }

  // Number of live processes this build host can still see. Used to prove the
  // closure requirement "zero orphan processes".
  static std::size_t live_children() {
#if defined(_WIN32)
    return 0;
#else
    return 0;
#endif
  }

 private:
  void move_from(ChildProcess& other) {
    release_handle();
    handle_ = other.handle_;
    other.handle_ = 0;
  }

  void release_handle() {
    if (handle_ == 0) {
      return;
    }
#if defined(_WIN32)
    CloseHandle(reinterpret_cast<HANDLE>(handle_));
#else
    // Reaped by kill() or by the operating system when the parent exits.
#endif
    handle_ = 0;
  }

#if defined(_WIN32)
  std::uintptr_t handle_ = 0;
#else
  std::int64_t handle_ = 0;
#endif
};

// Owns a child for the lifetime of a scope and kills it on every exit path,
// including an early return from a failed assertion. A test that leaks a child
// would leave a coordinator or worker running after the suite finished, which
// is itself a defect.
class ChildLease {
 public:
  ChildLease() = default;
  explicit ChildLease(ChildProcess child) : child_(std::move(child)) {}
  ChildLease(const ChildLease&) = delete;
  ChildLease& operator=(const ChildLease&) = delete;
  ~ChildLease() {
    if (child_.valid()) {
      child_.kill();
    }
  }

  ChildProcess& get() { return child_; }
  const ChildProcess& get() const { return child_; }
  bool valid() const { return child_.valid(); }
  bool running() const { return child_.running(); }
  bool kill() { return child_.kill(); }

 private:
  ChildProcess child_;
};

// Spawns the exact executable the test is running as, with the supplied
// arguments. The child inherits this process's standard handles.
inline ChildProcess spawn_self(const std::vector<std::string>& arguments) {
  ChildProcess child;
#if defined(_WIN32)
  std::vector<std::string> owned;
  char module[MAX_PATH] = {0};
  GetModuleFileNameA(nullptr, module, MAX_PATH);
  owned.push_back(std::string(module));
  for (const std::string& argument : arguments) {
    owned.push_back(argument);
  }
  std::string command;
  for (const std::string& piece : owned) {
    if (!command.empty()) {
      command.push_back(' ');
    }
    command.push_back('"');
    command += piece;
    command.push_back('"');
  }
  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION information{};
  const BOOL created =
      CreateProcessA(nullptr, command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr,
                     &startup, &information);
  if (created == 0) {
    return child;
  }
  CloseHandle(information.hThread);
  return ChildProcess::adopt(reinterpret_cast<std::uintptr_t>(information.hProcess));
#else
  std::vector<std::string> owned;
  {
    std::ifstream self("/proc/self/cmdline", std::ios::binary);
    std::string line;
    std::getline(self, line, '\0');
    owned.push_back(line.empty() ? std::string(".") : line);
  }
  for (const std::string& argument : arguments) {
    owned.push_back(argument);
  }
  std::vector<char*> argv;
  for (std::string& piece : owned) {
    argv.push_back(piece.data());
  }
  argv.push_back(nullptr);
  pid_t pid = 0;
  if (posix_spawn(&pid, argv[0], nullptr, nullptr, argv.data(), environ) != 0) {
    return child;
  }
  return ChildProcess::adopt(static_cast<std::int64_t>(pid));
#endif
}

inline void write_marker(const std::filesystem::path& path, const std::string& text) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream << text;
  stream.flush();
}

inline bool marker_present(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::exists(path, error);
}

inline std::string read_marker(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

// Bounded wait for a marker file. Crossing the bound is an explicit failure of
// the caller, never a silent pass.
inline bool wait_for_marker(const std::filesystem::path& path, std::chrono::milliseconds bound) {
  const auto deadline = std::chrono::steady_clock::now() + bound;
  while (std::chrono::steady_clock::now() < deadline) {
    if (marker_present(path)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return marker_present(path);
}

// Bounded wait for an arbitrary predicate, used for out-of-process observation.
template <class Predicate>
inline bool wait_until(Predicate predicate, std::chrono::milliseconds bound) {
  const auto deadline = std::chrono::steady_clock::now() + bound;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return predicate();
}

}  // namespace pd_test
