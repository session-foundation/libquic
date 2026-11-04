#pragma once

// Internal helpers shared by every libquic library; unlike internal.hpp this must not depend on
// ngtcp2 or libevent.

// IWYU pragma: begin_exports
#include "format.hpp"
#include "utils.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include <fmt/format.h>

namespace oxen::quic
{
    inline auto log_cat = oxen::log::Cat("quic");

    namespace log = oxen::log;

    using namespace log::literals;
}  // namespace oxen::quic

// IWYU pragma: end_exports
