INCLUDE_DIRECTORIES(${TinyVPN_SOURCE_DIR}/include)
LINK_DIRECTORIES(${TinyVPN_SOURCE_DIR}/third_lib)

SET(CLIENT_SRC vpn_client.cpp vpn_common.cpp vpn_client_cli.cpp)
SET(SERVER_SRC vpn_nat.cpp vpn_net.cpp vpn_server.cpp vpn_common.cpp vpn_server_cli.cpp)

ADD_EXECUTABLE(client ${CLIENT_SRC})
ADD_EXECUTABLE(server ${SERVER_SRC})

TARGET_LINK_LIBRARIES(client gflags pthread)
TARGET_LINK_LIBRARIES(server gflags pthread)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
