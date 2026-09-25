#pragma once

#include <compare>
#include <cstdint>
#include <functional>
#include <string>

namespace oxen::quic
{
    /// Identifies a timer registered with a JobQueue, as returned by `add_timer`.  Pass it to the
    /// JobQueue's `wake`, `repeat`, `stop` and `remove`; the JobQueue itself owns the timer, so
    /// discarding the id is how you say "run this until the queue dies".
    ///
    /// Note that a timer with no interval is perfectly valid: it simply never fires on its own, and
    /// runs only when `wake()`d.
    ///
    /// Default-constructible, referring to no timer; see the constructor below.
    ///
    /// Ids are unique process-wide rather than per-queue, and never reissued, so an id kept past its
    /// timer's removal (or handed to the wrong queue) is simply not found rather than matching
    /// something unrelated.
    ///
    /// The JobQueue is the lifetime scope: a timer lives exactly as long as the queue that created
    /// it, unless removed sooner, and stopping that queue cancels it.  So the question to design
    /// around is not "how do I keep this id alive" but "which queue should own this timer" -- put a
    /// timer on the queue whose lifetime already matches the state its callback touches, and its
    /// cancellation takes care of itself.
    ///
    /// An id means nothing on its own: every operation on it goes through the JobQueue that created
    /// it, and remembering which queue that is, is the caller's job.  That is free for a component
    /// using a single queue, since it holds that queue anyway -- but a component with timers on
    /// several queues, or on one it does not otherwise reference, must store the queue alongside
    /// the id.  There is deliberately no bundled {queue, id} handle: it could only hold a raw
    /// pointer to the queue, while looking like something safe to keep.
    ///
    /// This lives in its own header, with no libquic or libevent dependencies, so that holding a
    /// TimerID as a member does not require including loop.hpp.
    struct TimerID final
    {
        // 64-bit because the point of a process-wide counter is that an id is never reissued: a
        // stale id must fail to be found rather than silently match a live timer, which is only
        // true for as long as the counter cannot wrap.  32 bits is reachable on a long-running
        // node, and size_t would give that guarantee on 64-bit targets while quietly dropping it on
        // the 32-bit ones (armhf, win32).
        int64_t id{-1};

        /// A default-constructed TimerID refers to no timer at all.  Ids are allocated from 0 and
        /// are never negative, so -1 is never returned by add_timer() and is safe to use as an "I
        /// haven't made one yet" state without wrapping the id in a std::optional.  It behaves as
        /// any other unregistered id: stop() and remove() silently do nothing, wake() and repeat()
        /// throw.
        TimerID() = default;

        explicit TimerID(int64_t v) : id{v} {}
        TimerID(const TimerID&) = default;
        TimerID& operator=(const TimerID&) = default;

        /// True if this refers to a timer, i.e. is not default-constructed.  Note that this says
        /// nothing about whether that timer is still registered, only that an id was assigned.
        explicit operator bool() const { return id >= 0; }

        auto operator<=>(const TimerID&) const = default;

        std::string to_string() const;
        constexpr static bool to_string_formattable = true;
    };
}  //  namespace oxen::quic

namespace std
{
    template <>
    struct hash<oxen::quic::TimerID>
    {
        size_t operator()(const oxen::quic::TimerID& j) const noexcept { return hash<int64_t>{}(j.id); }
    };
}  // namespace std
