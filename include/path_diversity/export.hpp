// Path Diversity Fabric 1.0.0 - Summon Software Labs.
// Apache License 2.0. See LICENSE.
#pragma once

// Export macro for the vendor-neutral C++20 public surface. The library is
// usable as a static or shared library; nothing about the build type leaks
// into the interface.
#if defined(PATH_DIVERSITY_SHARED)
#if defined(_WIN32) || defined(_WIN64)
#if defined(path_diversity_EXPORTS)
#define PATH_DIVERSITY_API __declspec(dllexport)
#else
#define PATH_DIVERSITY_API __declspec(dllimport)
#endif
#else
#define PATH_DIVERSITY_API __attribute__((visibility("default")))
#endif
#else
#define PATH_DIVERSITY_API
#endif
