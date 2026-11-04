#pragma once

#include "address.hpp"

#include <ngtcp2/ngtcp2.h>

#include <string>
#include <tuple>

namespace oxen::quic
{
    // ngtcp2_addr doesn't own its storage: the returned value points into `a`'s sockaddr storage
    // (with `a`'s current length), and so `a` must outlive it.  ngtcp2 may write through the
    // pointer (e.g. when given a path to fill), in which case the bytes land directly in `a`.
    inline ngtcp2_addr ngtcp2_addr_ref(Address& a)
    {
        return {a, a.socklen()};
    }
    void ngtcp2_addr_ref(Address&&) = delete;

    // Wrapper for ngtcp2_path with remote/local components. Implicitly convertible
    // to ngtcp2_path*
    struct Path
    {
        friend class TestHelper;
        friend class Connection;

      public:
        Address local;
        Address remote;

      private:
        ngtcp2_path _path{ngtcp2_addr_ref(local), ngtcp2_addr_ref(remote), nullptr};

        void set_new_remote(const ngtcp2_addr& new_remote);

        // ngtcp2 records the length of an address it copies into `_path` there, not in the Address
        // it points into, so the two only agree while ngtcp2 never changes an address's length
        // (i.e. never switches it between IPv4 and IPv6).
        bool ngtcp2_lengths_match() const
        {
            return _path.local.addrlen == local.socklen() && _path.remote.addrlen == remote.socklen();
        }

      public:
        Path() = default;
        Path(const Address& l, const Address& r) : local{l}, remote{r} {}
        Path(const Path& p) : Path{p.local, p.remote} {}

        Path& operator=(const Path& p)
        {
            local = p.local;
            remote = p.remote;
            _path.local = ngtcp2_addr_ref(local);
            _path.remote = ngtcp2_addr_ref(remote);
            return *this;
        }

        bool operator==(const Path& other) const { return std::tie(local, remote) == std::tie(other.local, other.remote); }

        // template code to pass Path as ngtcp2_path into ngtcp2 functions
        template <typename T>
            requires std::same_as<T, ngtcp2_path>
        operator T*()
        {
            return &_path;
        }
        template <typename T>
            requires std::same_as<T, ngtcp2_path>
        operator const T*() const
        {
            return &_path;
        }

        Path invert() const { return {remote, local}; }

        std::string to_string() const;
        constexpr static bool to_string_formattable = true;
    };

}  // namespace oxen::quic

namespace std
{
    template <>
    struct hash<oxen::quic::Path>
    {
        size_t operator()(const oxen::quic::Path& addr) const noexcept
        {
            auto h = hash<oxen::quic::Address>{}(addr.local);
            h ^= hash<oxen::quic::Address>{}(addr.remote) + oxen::quic::inverse_golden_ratio + (h << 6) + (h >> 2);
            return h;
        }
    };
}  // namespace std
