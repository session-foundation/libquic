#pragma once

#include <memory>

struct event;

namespace oxen::quic
{
    struct event_deleter final
    {
        void operator()(::event* e) const;
    };

    using event_ptr = std::unique_ptr<::event, event_deleter>;

}  // namespace oxen::quic
