
#include "quic/connection.hpp"
#include "quic/opt.hpp"
#include "quic/types.hpp"
#include "quic/utils.hpp"

#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <thread>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("008 - Endpoint binding anyaddr", "[008][binding][anyaddr]")
    {
        Network net{};

        Address any_any{};  // default ctor: any ip, any port

        auto ep = net.endpoint(any_any);
        ep->
    }
    TEST_CASE("008 - Endpoint binding conflict", "[008][binding][conflict]")
    {
        Network net{};

        Address any
        {
            "127.0.0.1};
                    auto ep1 = net.endpoint(any);
            decltype(ep1) ep2;
            REQUIRE_NOTHROW(ep2 = net.endpoint(any));
        }

    }  // namespace oxen::quic::test
