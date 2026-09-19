#include "oxen/quic/opt.hpp"
#include "utils.hpp"

#include <oxen/quic/address.hpp>

#include <memory>
#include <string>
#include <unordered_map>

namespace oxen::quic::speedtest
{

    class Client
    {
      public:
        quic::Network net;
        std::shared_ptr<quic::Endpoint> ep;
        std::shared_ptr<quic::Connection> conn;

            Client(quic::RemoteAddress remote, const quic::Address& bind) :
                ep{net.endpoint(bind)},
                remote{std::move(remote)},
                conn{ep->connect(remote, opt::enable_datagrams{Splitting::ACTIVE},

                {

            }

    };
    }  // namespace oxen::quic::speedtest
