# Path Diversity Fabric 1.0.0 - Summon Software Labs.
# Apache License 2.0. See LICENSE.

set(PATH_DIVERSITY_EXAMPLES
  ex_link_disjoint
  ex_node_disjoint_endpoint_exemption
  ex_shared_risk_group_conflict
  ex_placement_diversity
  ex_incomplete_evidence_unknown
  ex_n_path_all_pairs
  ex_k_independent_subset
  ex_stale_topology
  ex_worker_reincarnation
  ex_coordinator_restart
  ex_persistence_recovery)

foreach(example ${PATH_DIVERSITY_EXAMPLES})
  add_executable(${example} ${example}.cpp example_support.hpp)
  target_link_libraries(${example} PRIVATE PathDiversityFabric path_diversity_project_options)
  target_include_directories(${example} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_definitions(${example} PRIVATE
    PATH_DIVERSITY_TEST_TEMP_ROOT="${CMAKE_CURRENT_BINARY_DIR}/tmp")
endforeach()
