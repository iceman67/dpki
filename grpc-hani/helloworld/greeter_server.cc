/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <iostream>
#include <memory>
#include <string>

#include <regex>
#include <vector>
#include <random>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_format.h"

#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

// #include "shamir.h"
#include "strtok.h"

extern "C" char *generate_share_strings(char *secret, int n, int t);

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;
using helloworld::OllehReply;
using helloworld::OllehRequest;
using helloworld::ShareReply;
using helloworld::ShareRequest;

ABSL_FLAG(uint16_t, port, 50051, "Server port for the service");

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Greeter::Service
{

  char *shares_string;
  const char *sk = "SK";

  void generate_shares()
  {
    grpc::string secret(sk);
    int n = 5;
    int t = 3;

    shares_string = generate_share_strings((char *)secret.c_str(), n, t);
  }

  void
  XOR(char *dst, const char *src)
  {
    const uint32_t MAGIC = 0x5f;

    // iterate over all chars in 'input', xor it with the magic number into dst.
    int i = 0;
    // Request for Share  ^ PubKey(Logger)
    for (; src[i]; i++)
    {
      dst[i] = src[i] ^ MAGIC;
    }
    // Redundant if dst is large enough, but be sure we add a terminating null
    // byte.
    dst[i] = '\0';
  }

  std::vector<std::string> tokenize(const std::string str, const std::regex re)
  {
    std::sregex_token_iterator it{str.begin(), str.end(), re, -1}; // -1: values between separators
    std::vector<grpc::string> tokenized{it, {}};

    tokenized.erase(std::remove_if(tokenized.begin(),
                                   tokenized.end(), [](std::string const &s)
                                   { return s.size() == 0; }),
                    tokenized.end());
    return tokenized;
  }

  Status SayHello(ServerContext *context, const HelloRequest *request,
                  HelloReply *reply) override
  {
    std::string prefix("Hello ");
    generate_shares();

    reply->set_message(prefix + request->name());
    return Status::OK;
  }

  Status SayOlleh(ServerContext *context, const OllehRequest *request,
                  OllehReply *reply) override
  {
    const uint16_t ENCODE_SIZE = 2048;

    char xored[ENCODE_SIZE];
    std::string prefix("Hello ");

    // reply->set_message(prefix + request->name());
    XOR(xored, (request->name()).c_str());
    reply->set_message(xored);
    return Status::OK;
  }

  // GetShare
  Status GetShare(ServerContext *context, const ShareRequest *request,
                  ShareReply *reply) override
  {
    const std::regex re(R"([\s|,]+)");
    const std::vector<std::string> tokenized = tokenize(shares_string, re);
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> distrib(0, 2); // distribution in range [1, 6]

    int r = distrib(rng);
    reply->set_message(tokenized[r].c_str());

    return Status::OK;
  }
};

void RunServer(uint16_t port)
{
  std::string server_address = absl::StrFormat("0.0.0.0:%d", port);
  GreeterServiceImpl service;

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int main(int argc, char **argv)
{
  absl::ParseCommandLine(argc, argv);
  RunServer(absl::GetFlag(FLAGS_port));
  return 0;
}
