# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


# Prefer GoogleTest (via vcpkg) when available; otherwise fall back to the
# custom-runner executables so the repo still builds without extra deps.
find_package(GTest CONFIG QUIET)

if (GTest_FOUND)
	include(GoogleTest)

	function(cose_copy_rust_dlls target_name)
		if(NOT WIN32)
			return()
		endif()

		set(_rust_dlls "")
		foreach(_libvar IN ITEMS COSE_FFI_BASE_LIB COSE_FFI_CERTIFICATES_LIB COSE_FFI_MST_LIB COSE_FFI_AKV_LIB COSE_FFI_TRUST_LIB)
			if(DEFINED ${_libvar} AND ${_libvar})
				set(_import_lib "${${_libvar}}")
				if(_import_lib MATCHES "\\.dll\\.lib$")
					string(REPLACE ".dll.lib" ".dll" _dll "${_import_lib}")
					list(APPEND _rust_dlls "${_dll}")
				endif()
			endif()
		endforeach()

		list(REMOVE_DUPLICATES _rust_dlls)
		foreach(_dll IN LISTS _rust_dlls)
			if(EXISTS "${_dll}")
				add_custom_command(
					TARGET ${target_name}
					POST_BUILD
					COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_dll}" $<TARGET_FILE_DIR:${target_name}>
				)
			endif()
		endforeach()

		# Also copy MSVC runtime + other dynamic deps when available.
		# This avoids failures on environments without global VC redistributables.
		if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.21")
			add_custom_command(
				TARGET ${target_name}
				POST_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_RUNTIME_DLLS:${target_name}> $<TARGET_FILE_DIR:${target_name}>
				COMMAND_EXPAND_LISTS
			)
		endif()

		# MSVC ASAN uses an additional runtime DLL that is not always present on PATH.
		# Copy it next to the executable to avoid 0xc0000135 during gtest discovery.
		if(MSVC AND COSE_ENABLE_ASAN)
			get_filename_component(_cl_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
			foreach(_asan_name IN ITEMS
				clang_rt.asan_dynamic-x86_64.dll
				clang_rt.asan_dynamic-i386.dll
				clang_rt.asan_dynamic-aarch64.dll
			)
				set(_asan_dll "${_cl_dir}/${_asan_name}")
				if(EXISTS "${_asan_dll}")
					add_custom_command(
						TARGET ${target_name}
						POST_BUILD
						COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_asan_dll}" $<TARGET_FILE_DIR:${target_name}>
					)
				endif()
			endforeach()
		endif()
	endfunction()

	add_executable(smoke_test smoke_test_gtest.cpp)
	target_link_libraries(smoke_test PRIVATE cose_sign1 GTest::gtest_main)
	cose_copy_rust_dlls(smoke_test)
	gtest_discover_tests(smoke_test DISCOVERY_MODE PRE_TEST DISCOVERY_TIMEOUT 30)

	if (COSE_FFI_TRUST_LIB)
		add_executable(real_world_trust_plans_test real_world_trust_plans_gtest.cpp)
		target_link_libraries(real_world_trust_plans_test PRIVATE cose_sign1 GTest::gtest_main)
		cose_copy_rust_dlls(real_world_trust_plans_test)

		get_filename_component(COSE_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
		set(COSE_TESTDATA_V1_DIR "${COSE_REPO_ROOT}/native/rust/cose_sign1_validation_certificates/testdata/v1")
		set(COSE_MST_JWKS_PATH "${COSE_REPO_ROOT}/native/rust/cose_sign1_validation_transparent_mst/testdata/esrp-cts-cp.confidential-ledger.azure.com.jwks.json")

		target_compile_definitions(real_world_trust_plans_test PRIVATE
			COSE_TESTDATA_V1_DIR="${COSE_TESTDATA_V1_DIR}"
			COSE_MST_JWKS_PATH="${COSE_MST_JWKS_PATH}"
		)

		gtest_discover_tests(real_world_trust_plans_test DISCOVERY_MODE PRE_TEST DISCOVERY_TIMEOUT 30)
	endif()
else()
	# Basic smoke test for C API
	add_executable(smoke_test smoke_test.c)
	target_link_libraries(smoke_test PRIVATE cose_sign1)
	add_test(NAME smoke_test COMMAND smoke_test)

	if (COSE_FFI_TRUST_LIB)
		add_executable(real_world_trust_plans_test real_world_trust_plans_test.c)
		target_link_libraries(real_world_trust_plans_test PRIVATE cose_sign1)

		get_filename_component(COSE_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
		set(COSE_TESTDATA_V1_DIR "${COSE_REPO_ROOT}/native/rust/cose_sign1_validation_certificates/testdata/v1")
		set(COSE_MST_JWKS_PATH "${COSE_REPO_ROOT}/native/rust/cose_sign1_validation_transparent_mst/testdata/esrp-cts-cp.confidential-ledger.azure.com.jwks.json")

		target_compile_definitions(real_world_trust_plans_test PRIVATE
			COSE_TESTDATA_V1_DIR="${COSE_TESTDATA_V1_DIR}"
			COSE_MST_JWKS_PATH="${COSE_MST_JWKS_PATH}"
		)

		add_test(NAME real_world_trust_plans_test COMMAND real_world_trust_plans_test)

		set(COSE_REAL_WORLD_TEST_NAMES
			compile_fails_when_required_pack_missing
			compile_succeeds_when_required_pack_present
			real_v1_policy_can_gate_on_certificate_facts
			real_scitt_policy_can_require_cwt_claims_and_mst_receipt_trusted_from_issuer
			real_v1_policy_can_validate_with_mst_only_by_bypassing_primary_signature
		)

		foreach(tname IN LISTS COSE_REAL_WORLD_TEST_NAMES)
			add_test(
				NAME real_world_trust_plans_test.${tname}
				COMMAND real_world_trust_plans_test --test ${tname}
			)
		endforeach()
	endif()
endif()
