#include "path.hpp"

#include "internal.hpp"

namespace oxen::quic
{
    void Path::set_new_remote(const ngtcp2_addr& new_remote)
    {
        remote = Address{new_remote.addr, new_remote.addrlen};
        _path.remote = ngtcp2_addr_ref(remote);
    }

    std::string Path::to_string() const
    {
        return "{{{} ➙ {}}}"_format(local, remote);
    }
}  // namespace oxen::quic
