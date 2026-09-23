#pragma once

#include "timer_id.hpp"
#include "utils.hpp"

#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>

struct event_base;

namespace oxen::quic
{
    using Job = std::function<void()>;

    class Loop;

    /// Deprecated; use JobQueue::add_timer() and the TimerID-based interface instead.  This class will
    /// be removed in a future release.  Note that dropping the last reference to a Ticker from
    /// inside its own callback is a use-after-free; add_timer() has no such restriction.
    struct Ticker
    {
        friend class Loop;
        friend class JobQueue;

      private:
        event_ptr ev;
        timeval interval;
        std::function<void()> f;

        void init_event(
                ::event_base* loop, std::chrono::microseconds _t, std::function<void()> task, bool start_immediately = true);

        Ticker() = default;

      public:
        /** Starts the repeating event on the given interval on Ticker creation.  Does nothing if
         *   already active.
            Returns:
                - true: event successfully started
                - false: event is already running, or failed to start the event
         */
        bool start();

        /** Stops the repeating event managed by Ticker.  Does nothing if not currently active.
            Returns:
                - true: event successfully stopped
                - false: event is already stopped, or failed to stop the event
         */
        bool stop();
    };

    /// An event loop task that can be fired multiple times, but is triggered manually when needed
    /// to schedule a callback call on the event loop.  Unlike using `call`/`call_soon`, calls to
    /// trigger/wake the event are idempotent: i.e. the event will be called only once regardless of
    /// how many wakeups there were prior to the call.  Once called, it will not be scheduled again
    /// until triggered at least once more.
    ///
    /// Construct via Loop::make_wakeable().
    ///
    /// Deprecated; use JobQueue::add_wakeable() and JobQueue::wake() instead.  This class will be
    /// removed in a future release.
    class Wakeable
    {
        friend class Loop;
        friend class JobQueue;

        event_ptr ev;
        std::function<void()> f;

        Wakeable() = default;

      public:
        /// Call to schedule f() to be called, if not already scheduled.
        void wake();
    };

    // Get an independent JobQueue to use for jobs, call_later, loop deleters, etc.
    //
    // Do not use this unless you know you need it.
    //
    // The interface is the same as `Loop::call` and similar, but a JobQueue can have a shorter lifetime
    // than the Loop on which it runs.  The purpose of this is if you have multiple components using
    // the same Loop and one of those components may have jobs queued which reference it *after* its
    // destructor, that component can instead own this JobQueue and those jobs will not be
    // processed, but anything else using the Loop will be unaffected.
    //
    // Effectively this allows a subqueue of events that can be cancelled (via JobQueue destruction)
    // without needing to cancel jobs of unrelated job queues.
    //
    // This queue can be stopped or destroyed *off* the loop thread, if necessary, but note that
    // stopping and destruction still requires that the loop thread is usable to perform the actual
    // destruction, and so the loop this class uses must outlive this queue.
    //
    // Timers created via add_timer() are owned by the queue and cancelled when it stops, so ids for
    // them may be discarded freely.  Deprecated Tickers and Wakeables are *not* owned by the queue:
    // if you hold one, you are responsible for making sure any concrete references to it
    // (especially shared_ptr) are gone before the JobQueue is.
    //
    // Two conventions run through the interface below.  Operations that schedule work -- call_soon,
    // call_later, add_timer, add_wakeable, wake, repeat -- throw if the queue has been stopped, or
    // if the timer they name is not registered: the work they were asked to do is not going to
    // happen, and saying so quietly would only defer the error.  Operations that cancel work --
    // stop, remove -- are instead silent about an id they cannot find, so that teardown paths can
    // call them unconditionally without tracking what was ever created.  (call() and call_get() sit
    // outside this: called from the loop thread they invoke f() directly and never touch the queue,
    // so they neither throw nor care whether it has stopped.)
    //
    // Note that "this component owns its own JobQueue" only bounds its callbacks' lifetimes if the
    // queue is destroyed *before* the state those callbacks touch, and for a component that hands
    // its queue to sub-components during construction that ordering is inverted: the queue has to
    // be declared before them, so reverse member destruction makes it one of the last things to
    // die, well after the state its jobs reference.  Call stop() explicitly at the top of the
    // owner's destructor in that case rather than relying on ~JobQueue.
    class JobQueue
    {
        friend class Loop;

        std::shared_ptr<bool> running{std::make_shared<bool>(true)};

        event_ptr job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;

        Loop& loop;

        // A registered timer: an event that may repeat on an interval, may be fired manually, or
        // both.  Defined in loop.cpp; the event's callback argument is a raw pointer to one of
        // these, which is why the shared_ptr below must outlive any in-flight dispatch.
        struct Entry;

        std::mutex registry_mutex;
        std::unordered_map<TimerID, std::shared_ptr<Entry>> registry;
        bool registry_stopped{false};

        // Looks up an id, returning a reference that keeps the entry (and its event) alive after
        // the registry lock is dropped.  Null if not registered.
        std::shared_ptr<Entry> find(TimerID id);

        // Cancels an entry's timer and forgets its interval, leaving it registered and wakeable.
        void disarm(Entry& e);

        TimerID add_entry(std::chrono::microseconds interval, std::function<void()> f, bool one_shot);

        void setup_job_waker();
        void process_job_queue();

      public:
        bool inside() const;

        JobQueue(Loop& l);

        // Cancels all jobs and timers in the queue and deletes this job queue's event from the
        // event loop.  This method does nothing if the queue has already been stopped.
        //
        // Cancelled means dropped, not flushed: a queued call_soon, a call_later whose delay has
        // not elapsed, and a timer that has been woken but not yet dispatched are all destroyed
        // without being run.  Nothing here gives a callback a last chance to fire.
        //
        // This is called automatically during destruction, but destruction is too late whenever the
        // queue outlives the state its callbacks reference -- in particular when it is a member
        // declared before the members it was handed to during construction.  See the note above the
        // class: such owners should call this at the top of their destructor.
        //
        // Stopping is terminal (i.e. there is no way to restart a queue other than replacing it).
        //
        // Note that this method requires the event loop and will block until the owning Loop is
        // able to process it.
        void stop();

        // Calls stop() if not already called.
        ~JobQueue();

        // Returns a pointer deleter that defers the actual destruction call to this JobQueue
        template <typename T>
        auto loop_deleter()
        {
            return [this](T* ptr) { call_get([ptr] { delete ptr; }); };
        }

        // Returns a pointer deleter that defers invocation of a custom deleter to this JobQueue
        template <typename T, std::invocable<T*> Callable>
        auto wrapped_deleter(Callable f)
        {
            return [this, func = std::move(f)](T* ptr) mutable {
                return call_get([f = std::move(func), ptr]() { return f(ptr); });
            };
        }

        // Similar in concept to std::make_shared<T>, but it creates the shared pointer with a
        // custom deleter that dispatches actual object destruction to this JobQueue for thread
        // safety, and waits for destruction of the overlying object to complete before returning.
        template <typename T, typename... Args>
        std::shared_ptr<T> make_shared(Args&&... args)
        {
            auto* ptr = new T{std::forward<Args>(args)...};
            return std::shared_ptr<T>{ptr, loop_deleter<T>()};
        }

        // Similar to the above make_shared, but instead of forwarding arguments for the
        // construction of the object, it creates the shared_ptr from the already created object ptr
        // and wraps the object's deleter in a wrapped_deleter
        template <typename T, std::invocable<T*> Callable>
        std::shared_ptr<T> shared_ptr(T* obj, Callable&& deleter)
        {
            return std::shared_ptr<T>(obj, wrapped_deleter<T>(std::forward<Callable>(deleter)));
        }

        /// Calls `f()` on the JobQueue.  If the caller is already in the Loop thread then
        /// f() is called immediately; otherwise it is scheduled at the end of the queue.
        template <std::invocable<> Callable>
        void call(Callable&& f)
        {
            if (inside())
            {
                f();
            }
            else
            {
                call_soon(std::forward<Callable>(f));
            }
        }

        // Calls `f()` on the JobQueue and returns its value.  If this is called from within the
        // Loop thread then this simply calls and returns the result of `f()`.  If *not* in
        // the Loop thread then a call to `f()` is scheduled on the JobQueue for the next available
        // opportunity and then the current thread blocks until that call is invoked, then returns
        // it back to the caller.
        template <typename Callable, typename Ret = decltype(std::declval<Callable>()())>
        Ret call_get(Callable&& f)
        {
            if (inside())
            {
                return f();
            }

            struct CallGetter
            {
                std::shared_ptr<std::promise<Ret>> prom{std::make_shared<std::promise<Ret>>()};
                Callable& f;

                void operator()()
                {
                    try
                    {
                        if constexpr (!std::is_void_v<Ret>)
                            prom->set_value(f());
                        else
                        {
                            f();
                            prom->set_value();
                        }
                    }
                    catch (...)
                    {
                        prom->set_exception(std::current_exception());
                    }
                }
            };

            CallGetter g{.f = f};
            auto fut = g.prom->get_future();

            call_soon(std::move(g));

            return fut.get();
        }

        /// Schedules a call of `f()` on the JobQueue after a delay.  Fires once and then disposes
        /// of itself; there is deliberately no id for it, and so no way to cancel it.
        ///
        /// If the queue is stopped or destroyed before the delay elapses then `f` is *dropped*, not
        /// run: shutdown cancels the pending call and destroys the callback without invoking it.
        /// Since there is no id to cancel, a delayed call outliving its queue is the one case worth
        /// planning for -- capture weakly, or keep the state it touches alive past the queue.
        ///
        /// Throws if the queue has been stopped.
        void call_later(std::chrono::microseconds delay, std::function<void()> f);

        /// Registers `f()` to be called repeatedly, every `interval`, starting `interval` from now.
        ///
        /// An interval of zero or less registers the callback with no timer running at all: it will
        /// then run only when explicitly fired via `wake()`.  The interval can be changed, or added
        /// and removed, at any point afterwards via `repeat()`.
        ///
        /// The returned id is how you reach the timer again, through this same queue and no other
        /// (see TimerID).  The JobQueue owns the timer itself, so discarding the id simply means it
        /// runs until the queue is destroyed.  A timer is never disposed of on its own: it lives
        /// until `remove()` or the queue's death.
        ///
        /// Throws if the queue has been stopped, or if `f` is empty.
        TimerID add_timer(std::chrono::microseconds interval, std::function<void()> f);

        /// Registers `f()` with no initial timer and so will not be scheduled to be called.  This is intended
        /// for cases where a timer is needed, but will be scheduled at a later point.
        ///
        /// Equivalent to `add_timer(0us, f)`, throws in the same cases.
        [[nodiscard]] TimerID add_timer(std::function<void()> f);

        /// Registers `f()` to be run only when fired via `wake()`.
        ///
        /// This creates a wakeable function that can be triggered by passing the returned TimerID
        /// into wake.  This is simply an alias for `add_timer(f)` (a timer without an actual repeat
        /// interval set up is itself manually wakeable), but this alias is strongly recommended to
        /// signal intent when a plain wakeable function is intended.
        ///
        /// Waking this function is idempotent (i.e. multiple calls before the function actually
        /// runs are collapsed): see `wake()`.
        ///
        /// Throws if the queue has been stopped, or if `f` is empty.
        [[nodiscard]] TimerID add_wakeable(std::function<void()> f);

        /// Fires `id` as soon as the event loop can get to it, regardless of whether it has a
        /// repeat timer or when that timer is next due.
        ///
        /// This is idempotent: repeated calls before it actually runs schedule just one call.
        ///
        /// Note that firing a repeating timer *resets its cycle*: the next timed run happens one
        /// full interval after this call, not at the time it would otherwise have been due.  (The
        /// exception is a fire that coincides with an already-due tick, which collapses into it and
        /// leaves the cycle alone.)
        ///
        /// Throws if `id` is not a registered timer.
        void wake(TimerID id);

        /// Sets `id` to repeat every `interval`, measured from now, replacing whatever repeat it
        /// had.  An interval of zero or less stops it repeating, equivalent to `stop(id)`.
        ///
        /// If `now` is true it is additionally fired immediately, as per `wake()`.
        ///
        /// Setting a positive interval never blocks.  Descheduling (an interval of zero or less)
        /// blocks in the same circumstances as `stop()`, which is what it is equivalent to.
        ///
        /// Throws if `id` is not a registered timer.
        void repeat(TimerID id, std::chrono::microseconds interval, bool now = false);

        /// Returns true if `id` currently has a repeat scheduled, i.e. if it will fire on its own.
        /// False if it is registered but wake-only, whether because it was created that way or
        /// because it has been `stop()`ped, and false for an id that is not registered at all.
        ///
        /// This asks only about the repeat: a timer that has been `wake()`d but not yet dispatched
        /// is not armed, because libevent gives us no way to see a pending manual fire.
        ///
        /// Intended for writing an idempotent "make the timers match this table" pass without
        /// having to track arm state separately.
        ///
        /// This is a query, not a lock: `armed()` followed by `repeat()` or `stop()` is
        /// check-then-act, and the registry is not held between the two.  Such a pass is therefore
        /// only idempotent if nothing else can change those timers while it runs -- because every
        /// change to them goes through the loop thread, say, or because the caller serialises them
        /// itself.  Otherwise a timer can be armed between the check and the act, so the "already
        /// correct, leave it alone" branch re-phases a cycle that was fine, or removed between
        /// them, so the `repeat()` throws.
        bool armed(TimerID id);

        /// Deschedules `id`: cancels its repeat, and cancels any pending `wake()` that hasn't been
        /// dispatched yet.  It remains registered, and stays wakeable: `wake()` will still run it,
        /// exactly once per call, without resuming the repeat.  This is *not* removal.
        ///
        /// The interval is forgotten rather than remembered, so restarting means naming one again
        /// via `repeat()`.  This is the exact inverse of `repeat()`: a timer can be turned into a
        /// wake-only callback and back as often as you like.
        ///
        /// Like `remove()`, and for the same reason, this *blocks* when called from a thread other
        /// than the event loop's while this timer's callback happens to be running, so that on
        /// return the callback is guaranteed not to be executing.  (So don't call it while holding
        /// a lock the callback also wants.)  From the event loop thread, including from inside the
        /// timer's own callback, it never blocks.
        ///
        /// Returns true if a repeat was scheduled when this ran.  Two caveats: a cancelled pending
        /// `wake()` is not reported, because libevent gives us no way to see one; and the check and
        /// the cancel are not one atomic step, so with another thread mutating the same timer this
        /// is "it was armed when we looked" rather than "we are the ones who cancelled it".
        ///
        /// Does nothing, and returns false, if `id` is not a registered timer.
        bool stop(TimerID id);

        /// Removes `id` entirely, cancelling it and disposing of the callback.  Returns true if the
        /// timer existed; does nothing, silently, if it did not.
        ///
        /// When called from a thread other than the event loop's, this *blocks* until the timer's
        /// callback finishes if it happens to be running, so that on return the callback is
        /// guaranteed not to be executing.  (Consequently: do not call this while holding a lock
        /// that the callback also wants.)  Called from the event loop thread, including from inside
        /// the timer's own callback, it never blocks.
        bool remove(TimerID id);

        static void activate(::event& evt);

        /// Schedules a call of `f()` at the next available opportunity on the JobQueue.  Unlike
        /// `call()`, `call_soon()` never calls f() immediately even if already inside the Loop
        /// thread.
        ///
        /// Throws if the queue has been stopped.
        template <std::invocable<> Callable>
        void call_soon(Callable f)
        {
            {
                std::lock_guard lock{job_queue_mutex};
                if (!*running)
                    throw std::runtime_error{"Attempting to queue job onto stopped loop."};
                job_queue.emplace(std::move(f));
            }

            activate(*job_waker);
        }

        /// Takes any type of shared_ptr and schedules a reset of that shared pointer on the
        /// JobQueue.  Asyncronous.
        template <typename T>
        void reset_soon(std::shared_ptr<T>&& ptr)
        {
            call_soon([ptr = std::move(ptr)]() mutable { ptr.reset(); });
        }
    };

    class Loop
    {
        friend class JobQueue;

      protected:
        std::unique_ptr<::event_base, void (*)(struct ::event_base*)> ev_loop;
        std::thread loop_thread;
        std::thread::id loop_thread_id;

      private:
        JobQueue main_queue{*this};

        std::shared_ptr<Ticker> make_ticker();

      public:
        Loop();

        Loop(const Loop&) = delete;
        Loop(Loop&&) = delete;
        Loop& operator=(Loop&&) = delete;
        Loop& operator=(Loop) = delete;

        virtual ~Loop();

        ::event_base* get_event_base() const { return ev_loop.get(); }

        bool inside() const { return std::this_thread::get_id() == loop_thread_id; }

        // See JobQueue::wrapped_deleter, applies to Loop's main event queue.
        template <typename T, std::invocable<T*> Callable>
        auto wrapped_deleter(Callable&& f)
        {
            return main_queue.wrapped_deleter<T>(std::forward<Callable>(f));
        }

        // See JobQueue::make_shared, applies to Loop's main event queue.
        template <typename T, typename... Args>
        std::shared_ptr<T> make_shared(Args&&... args)
        {
            return main_queue.make_shared<T>(std::forward<Args>(args)...);
        }

        // See JobQueue::shared_ptr, applies to Loop's main event queue.
        template <typename T, std::invocable<T*> Callable>
        std::shared_ptr<T> shared_ptr(T* obj, Callable&& deleter)
        {
            return main_queue.shared_ptr<T>(obj, std::forward<Callable>(deleter));
        }

        // See JobQueue::call, applies to Loop's main event queue.
        template <std::invocable<> Callable>
        void call(Callable&& f)
        {
            main_queue.call(std::forward<Callable>(f));
        }

        // See JobQueue::call_get, applies to Loop's main event queue.
        template <typename Callable, typename Ret = decltype(std::declval<Callable>()())>
        Ret call_get(Callable&& f)
        {
            return main_queue.call_get(std::forward<Callable>(f));
        }

        /// Sets up a task `f()` to be called on the event loop periodically.
        ///
        /// `interval` controls the interval on which the task will be called.
        ///
        /// `start_immediately` controls whether the task is scheduled on the event loop right away
        /// (true, the default), or not (false).  If not started immediately then the task will not
        /// fire until `start()` is called on it.  (Note that this parameter does not mean "call
        /// immediately" -- it simply controls whether the initial timer for the first call is
        /// started or not).
        ///
        /// The owner of the Ticker is responsible for making sure it does not outlive the Loop
        /// from which it was created.
        template <std::invocable<> Callable>
        [[deprecated("use add_timer() instead")]] [[nodiscard]] std::shared_ptr<Ticker> call_every(
                std::chrono::microseconds interval, Callable&& f, bool start_immediately = true)
        {
            auto h = make_ticker();
            h->init_event(get_event_base(), interval, std::forward<Callable>(f), start_immediately);
            return h;
        }

        // See JobQueue::call_later, applies to Loop's main event queue.
        void call_later(std::chrono::microseconds delay, std::function<void()> f)
        {
            main_queue.call_later(delay, std::move(f));
        }

        // See JobQueue::add_timer, applies to Loop's main event queue.
        TimerID add_timer(std::chrono::microseconds interval, std::function<void()> f)
        {
            return main_queue.add_timer(interval, std::move(f));
        }

        // See JobQueue::add_timer, applies to Loop's main event queue.
        TimerID add_timer(std::function<void()> f) { return main_queue.add_timer(std::move(f)); }

        // See JobQueue::add_wakeable, applies to Loop's main event queue.
        TimerID add_wakeable(std::function<void()> f) { return main_queue.add_wakeable(std::move(f)); }

        // See JobQueue::wake, applies to Loop's main event queue.
        void wake(TimerID id) { main_queue.wake(id); }

        // See JobQueue::repeat, applies to Loop's main event queue.
        void repeat(TimerID id, std::chrono::microseconds interval, bool now = false)
        {
            main_queue.repeat(id, interval, now);
        }

        // See JobQueue::armed, applies to Loop's main event queue.
        bool armed(TimerID id) { return main_queue.armed(id); }

        // See JobQueue::stop, applies to Loop's main event queue.
        bool stop(TimerID id) { return main_queue.stop(id); }

        // See JobQueue::remove, applies to Loop's main event queue.
        bool remove(TimerID id) { return main_queue.remove(id); }

        /// Creates a Wakeable event tied to this event loop that can be manually triggered when
        /// desired to schedule an invocation of the callback.  Unlike call_soon, this is idempotent
        /// (i.e. multiple wakeups before it actually runs does not schedule multiple calls).  Note
        /// that this call only constructs the event, but does not initially schedule it.
        [[deprecated("use add_wakeable() instead")]] std::shared_ptr<Wakeable> make_wakeable(std::function<void()> hook);

        // See JobQueue::call_soon, applies to Loop's main event queue.
        template <std::invocable<> Callable>
        void call_soon(Callable&& f)
        {
            main_queue.call_soon(std::forward<Callable>(f));
        }

        // See JobQueue::reset_soon, applies to Loop's main event queue.
        template <typename T>
        void reset_soon(std::shared_ptr<T>&& ptr)
        {
            call_soon([ptr = std::move(ptr)]() mutable { ptr.reset(); });
        }
    };
}  //  namespace oxen::quic
