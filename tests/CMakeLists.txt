# Path Diversity Fabric 1.0.0 - Summon Software Labs.
# Apache License 2.0. See LICENSE.

set(PATH_DIVERSITY_TEST_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR})

function(path_diversity_add_test name)
  add_executable(${name} ${name}.cpp test_support.hpp process_helper.hpp)
  target_link_libraries(${name} PRIVATE PathDiversityFabric path_diversity_project_options)
  target_include_directories(${name} PRIVATE ${PATH_DIVERSITY_TEST_INCLUDE_DIRS})
  target_compile_definitions(${name} PRIVATE
    PATH_DIVERSITY_TEST_TEMP_ROOT="${CMAKE_CURRENT_BINARY_DIR}/tmp")
  add_test(NAME ${name} COMMAND ${name})
endfunction()

path_diversity_add_test(pd_test_core)
path_diversity_add_test(pd_test_oracle)
path_diversity_add_test(pd_test_proofs)
path_diversity_add_test(pd_test_kset)
path_diversity_add_test(pd_test_lifecycle)
path_diversity_add_test(pd_test_invalidation)
path_diversity_add_test(pd_test_authority)
path_diversity_add_test(pd_test_persistence)
path_diversity_add_test(pd_test_persistence_adversarial)
path_diversity_add_test(pd_test_wire)
path_diversity_add_test(pd_test_limits)
path_diversity_add_test(pd_test_property)
path_diversity_add_test(pd_test_concurrency)
path_diversity_add_test(pd_test_distributed)
path_diversity_add_test(pd_test_explanation)
path_diversity_add_test(pd_test_snapshot)
path_diversity_add_test(pd_test_synthetic)

# The cross-process suites spawn the test executable itself, so they need no
# other target to exist first.
