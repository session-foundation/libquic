#pragma once

#include "utils.hpp"

#include <future>
#include <list>
#include <memory>
#include <queue>
#include <thread>

struct event_base;

namespace oxen::quic
{
    using Job = std::function<void()>;

    class Loop;

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
    // If you keep objects alive which you created with this queue, e.g. tickers, wakeables, etc.
    // you are responsible for making sure any concrete references to them (especially shared_ptr)
    // are gone before the JobQueue is.  Their destructors are (necessarily and intentionally) jobs
    // on the job queue from which they spawned.
    class JobQueue
    {
        friend class Loop;

        std::shared_ptr<bool> running{std::make_shared<bool>(true)};

        event_ptr job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;

        Loop& loop;

        void add_oneshot_event(std::chrono::microseconds delay, std::function<void()> hook);

        // call_later events aren't guaranteed to get properly disposed off if the job queue is
        // destroyed before it fires, so we stash it in here temporarily and remove it when fired.
        // During the JobQueue destructor, then any unfired events need to be cleaned up.
        struct OneShotDelayed;
        std::list<OneShotDelayed*> delayed_events;

        void setup_job_waker();
        void process_job_queue();

      public:
        bool inside() const;

        JobQueue(Loop& l);

        // Cancels all jobs in the queue and deletes this job queue's event from the event loop.
        // This is normally called automatically during destruction, but can be called before
        // destruction if needed.  This method does nothing if the queue has already been stopped.
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

        /// Schedules a call of `f()` on the JobQueue after a delay.
        template <std::invocable<> Callable>
        void call_later(std::chrono::microseconds delay, Callable hook)
        {
            if (inside())
            {
                add_oneshot_event(delay, std::move(hook));
            }
            else
            {
                call_soon([this, func = std::move(hook), target_time = get_time() + delay]() mutable {
                    auto now = get_time();

                    if (now >= target_time)
                        func();
                    else
                        add_oneshot_event(
                                std::chrono::duration_cast<std::chrono::microseconds>(target_time - now), std::move(func));
                });
            }
        }

        static void activate(::event& evt);

        /// Schedules a call of `f()` at the next available opportunity on the JobQueue.  Unlike
        /// `call()`, `call_soon()` never calls f() immediately even if already inside the Loop
        /// thread.
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
        [[nodiscard]] std::shared_ptr<Ticker> call_every(
                std::chrono::microseconds interval, Callable&& f, bool start_immediately = true)
        {
            auto h = make_ticker();
            h->init_event(get_event_base(), interval, std::forward<Callable>(f), start_immediately);
            return h;
        }

        // See JobQueue::call_later, applies to Loop's main event queue.
        template <std::invocable<> Callable>
        void call_later(std::chrono::microseconds delay, Callable&& hook)
        {
            main_queue.call_later(delay, std::forward<Callable>(hook));
        }

        /// Creates a Wakeable event tied to this event loop that can be manually triggered when
        /// desired to schedule an invocation of the callback.  Unlike call_soon, this is idempotent
        /// (i.e. multiple wakeups before it actually runs does not schedule multiple calls).  Note
        /// that this call only constructs the event, but does not initially schedule it.
        std::shared_ptr<Wakeable> make_wakeable(std::function<void()> hook);

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
