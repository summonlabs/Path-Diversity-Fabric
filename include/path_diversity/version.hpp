// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "path_diversity/export.hpp"

namespace path_diversity {

inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 0;

// Independently versioned compatibility surfaces. These are deliberately not
// tied to the package version: a persistence or wire format may stay stable
// across product releases and may change inside one.
inline constexpr std::uint32_t kPersistenceFormatVersion = 1;
inline constexpr std::uint32_t kCanonicalEncodingVersion = 1;
inline constexpr std::uint32_t kDigestSchemeVersion = 1;
inline constexpr std::uint16_t kWireProtocolVersion = 1;
inline constexpr std::uint32_t kDiversityRuleSetVersion = 1;

PATH_DIVERSITY_API std::string_view library_name() noexcept;
PATH_DIVERSITY_API std::string_view version_string() noexcept;
PATH_DIVERSITY_API std::string version_report();

}  // namespace path_diversity
