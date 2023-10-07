get_filename_component(helloworld_proto "../protos/helloworld.proto" ABSOLUTE)
get_filename_component(helloworld_proto_path "${helloworld_proto}" PATH)

set(helloworld_proto_sources "${CMAKE_CURRENT_BINARY_DIR}/helloworld.pb.cc")
set(helloworld_proto_headers "${CMAKE_CURRENT_BINARY_DIR}/helloworld.pb.h")
set(helloworld_grpc_sources "${CMAKE_CURRENT_BINARY_DIR}/helloworld.grpc.pb.cc")
set(helloworld_grpc_headers "${CMAKE_CURRENT_BINARY_DIR}/helloworld.grpc.pb.h")

set(shamir_headers "../extra/shamir.h")
set(shamir_sources "../extra/shamir.c")
set(strtok_headers "../extra/strtok.h")
set(strtok_sources "../extra/strtok.c")


add_custom_command(
        OUTPUT "${helloworld_proto_sources}" "${helloworld_proto_headers}" "${helloworld_grpc_sources}" "${helloworld_grpc_headers}"
        COMMAND ${_PROTOBUF_PROTOC}
        ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}" --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${helloworld_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${helloworld_proto}"
        DEPENDS "${helloworld_proto}")

include_directories("${CMAKE_CURRENT_BINARY_DIR}")

add_library(helloworld_grpc_proto
        ${helloworld_proto_sources}
        ${helloworld_proto_headers}
        ${helloworld_grpc_sources}
        ${helloworld_grpc_headers}
        )

add_library(Shamir STATIC
        ${shamir_sources}
        ${shamir_headers}
        ${strtok_sources}
        ${strtok_headers}
)
 
target_link_libraries(helloworld_grpc_proto
        ${_PROTOBUF_LIBPROTOBUF}
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        )


foreach(_target greeter_client greeter_server)
    add_executable(${_target} "${_target}.cc" )
    target_link_libraries(${_target}
            Shamir
            helloworld_grpc_proto
            absl::flags
            absl::flags_parse
            ${_PROTOBUF_LIBPROTOBUF}
            ${_REFLECTION}
            ${_GRPC_GRPCPP})
endforeach()
