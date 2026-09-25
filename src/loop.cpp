#include "loop.hpp"

#include "internal.hpp"

#include <event2/event.h>
#include <event2/thread.h>

#include <fmt/ranges.h>

#include <atomic>
#include <mutex>

namespace oxen::quic
{
    static auto ev_cat = log::Cat("ev-loop");

    static void setup_libevent_logging()
    {
        event_set_log_callback([](int severity, const char* msg) {
            switch (severity)
            {
                case _EVENT_LOG_ERR:
                    log::error(ev_cat, "{}", msg);
                    break;
                case _EVENT_LOG_WARN:
                    log::warning(ev_cat, "{}", msg);
                    break;
                case _EVENT_LOG_MSG:
                    log::info(ev_cat, "{}", msg);
                    break;
                case _EVENT_LOG_DEBUG:
                default:
                    log::debug(ev_cat, "{}", msg);
                    break;
            }
        });
    }

    bool Ticker::start()
    {
        if (event_add(ev.get(), &interval) != 0)
        {
            log::warning(log_cat, "Ticker failed to start repeating event!");
            return false;
        }

        return true;
    }

    bool Ticker::stop()
    {
        if (ev && event_del(ev.get()) != 0)
        {
            log::warning(log_cat, "Ticker failed to pause repeating event!");
            return false;
        }
        return true;
    }

    void Ticker::init_event(
            ::event_base* loop, std::chrono::microseconds t, std::function<void()> task, bool start_immediately)
    {
        f = std::move(task);

        interval = loop_time_to_timeval(t);

        ev.reset(event_new(
                loop,
                -1,
                EV_PERSIST,
                [](evutil_socket_t, short, void* s) {
                    try
                    {
                        auto* self = reinterpret_cast<Ticker*>(s);
                        if (not self->f)
                        {
                            log::warning(log_cat, "Ticker does not have a callback to execute!");
                            return;
                        }
                        // execute callback
                        self->f();
                    }
                    catch (const std::exception& e)
                    {
                        log::warning(log_cat, "Ticker caught exception: {}", e.what());
                    }
                },
                this));

        if (start_immediately and not start())
            log::warning(log_cat, "Failed to immediately start repeating event!");
    }

    static std::vector<std::string_view> get_ev_methods()
    {
        std::vector<std::string_view> ev_methods_avail;
        for (const char** methods = event_get_supported_methods(); methods && *methods; methods++)
            ev_methods_avail.emplace_back(*methods);
        return ev_methods_avail;
    }

    static ::event_base* make_ev_loop()
    {

#ifdef _WIN32
        {
            WSADATA ignored;
            if (int err = WSAStartup(MAKEWORD(2, 2), &ignored); err != 0)
            {
                log::critical(log_cat, "WSAStartup failed to initialize the windows socket layer ({:x})", err);
                throw std::runtime_error{"Unable to initialize windows socket layer"};
            }
        }
#endif

        // Older versions of libevent do not like having the thread setup called multiple times, so
        // this must stay a once-only initialization even if multiple Loops are constructed
        // concurrently from different threads.
        static std::once_flag ev_init_once;
        std::call_once(ev_init_once, [] {
            setup_libevent_logging();

#ifdef _WIN32
            evthread_use_windows_threads();
#else
            evthread_use_pthreads();
#endif
        });

        static std::vector<std::string_view> ev_methods_avail = get_ev_methods();
        log::debug(
                log_cat,
                "Starting libevent {}; available backends: {}",
                event_get_version(),
                "{}"_format(fmt::join(ev_methods_avail, ", ")));

        std::unique_ptr<event_config, decltype(&event_config_free)> ev_conf{event_config_new(), event_config_free};
        event_config_set_flag(ev_conf.get(), EVENT_BASE_FLAG_PRECISE_TIMER);
        event_config_set_flag(ev_conf.get(), EVENT_BASE_FLAG_NO_CACHE_TIME);
        event_config_set_flag(ev_conf.get(), EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);

        auto ev_loop = event_base_new_with_config(ev_conf.get());
        log::debug(log_cat, "Started libevent loop with backend {}", event_base_get_method(ev_loop));
        return ev_loop;
    }

    Loop::Loop() : ev_loop{make_ev_loop(), ::event_base_free}
    {
        std::promise<void> p;
        loop_thread = std::thread{[this, &p] {
            log::debug(log_cat, "Starting event loop run");
            p.set_value();
            event_base_loop(ev_loop.get(), EVLOOP_NO_EXIT_ON_EMPTY);
            log::debug(log_cat, "Event loop run returned, thread finished");
        }};

        loop_thread_id = loop_thread.get_id();
        p.get_future().get();

        log::info(log_cat, "libevent loop is started");
    }

    std::string TimerID::to_string() const
    {
        return "Timer[{}]"_format(id);
    }

    struct JobQueue::Entry
    {
        // Used only by the dispatch callback, to dispose of a one-shot once it has fired.  ~Entry
        // must never touch this: entries are destroyed by libevent finalizers, which can run from
        // event_base_free *after* the JobQueue has been destroyed (it is declared after ev_loop in
        // Loop, so it dies first).
        JobQueue* jq;
        TimerID id;

        event_ptr ev;
        std::function<void()> f;
        bool one_shot;

        Entry(JobQueue* jq, TimerID id, std::function<void()> f, bool one_shot) :
                jq{jq}, id{id}, f{std::move(f)}, one_shot{one_shot}
        {}

        static void dispatch(evutil_socket_t, short, void* arg)
        {
            auto* e = static_cast<Entry*>(arg);

            try
            {
                e->f();
            }
            catch (const std::exception& ex)
            {
                log::warning(log_cat, "Timer callback raised an exception: {}", ex.what());
            }
            catch (...)
            {
                log::warning(log_cat, "Timer callback raised an unknown exception");
            }

            if (e->one_shot)
                e->jq->remove(e->id);
        }

        // Disposes of an entry once nothing references it any more.  The last reference can be
        // dropped from any thread, and in particular from inside the timer's own callback, so neither
        // the event nor the std::function may be destroyed here: event_free_finalize hands both to
        // libevent, which frees them at a point where it knows the callback is not running.
        // Finalizers still pending when the loop goes away are run by event_base_free -- that is,
        // the deletion happens; the timer's own callback is destroyed rather than given a last run.
        static void dispose(Entry* e)
        {
            if (auto* ev = e->ev.release())
                event_free_finalize(0, ev, [](::event*, void* arg) { delete static_cast<Entry*>(arg); });
            else
                delete e;
        }
    };

    JobQueue::JobQueue(Loop& l) : loop{l}
    {
        setup_job_waker();
    }

    JobQueue::~JobQueue()
    {
        log::debug(log_cat, "Destryoing job queue.");
        if (job_waker)
            stop();
    }

    void JobQueue::stop()
    {
        // Synchronization point: if we aren't on the loop, recurse into it:
        if (!loop.inside())
        {
            loop.call_get([this] { stop(); });
            return;
        }

        {
            // Destroying a dropped job runs arbitrary code -- a captured callback's destructor,
            // for instance -- which may want to touch this queue, so the jobs must be destroyed
            // outside both of our mutexes.  (Why does std::queue not have a clear() method?)
            std::queue<Job> dropped;

            {
                std::lock_guard l{job_queue_mutex};
                if (!job_waker)
                    return;

                log::debug(log_cat, "Stopping/cancelling job queue events");
                *running = false;

                job_waker.reset();

                job_queue.swap(dropped);
            }
        }

        // Dropping our references requests finalization of each timer's event; libevent runs those
        // finalizers either during the loop's remaining iterations or, failing that, from
        // event_base_free, so no entry is leaked by us going away first.  Note that finalization is
        // only the *cleanup*: a timer that was armed or already woken has its callback destroyed
        // here, not invoked.
        std::lock_guard l{registry_mutex};
        registry_stopped = true;
        registry.clear();
    }

    Loop::~Loop()
    {
        log::debug(log_cat, "Shutting down loop...");

        // JobQueue has a canary such that if it's processing jobs as it is destroyed it should be
        // safe, but we *do* want to stop/destroy it before general member destruction (and on the
        // loop thread, implemented by stop() itself).
        main_queue.stop();

        event_base_loopbreak(ev_loop.get());
        loop_thread.join();

        log::info(log_cat, "Loop shutdown complete");

#ifdef _WIN32
        WSACleanup();
#endif
    }

    std::shared_ptr<Ticker> Loop::make_ticker()
    {
        return make_shared<Ticker>();
    }

    std::shared_ptr<Wakeable> Loop::make_wakeable(std::function<void()> callback)
    {
        if (!callback)
        {
            // FIXME: should this throw/assert?
            log::error(log_cat, "Not making Wakeable with empty callback.");
            return nullptr;
        }

        auto w = make_shared<Wakeable>();
        w->f = std::move(callback);
        w->ev.reset(event_new(
                ev_loop.get(),
                -1,
                0,
                [](evutil_socket_t, short, void* w) {
                    auto* wakeable = static_cast<Wakeable*>(w);
                    wakeable->f();
                },
                w.get()));
        return w;
    }

    void Wakeable::wake()
    {
        event_active(ev.get(), 0, 0);
    }

    void JobQueue::setup_job_waker()
    {
        // Almost identical to the generic make_wakeable, except that we avoid the std::function and
        // its implicit virtual function call.
        job_waker.reset(event_new(
                loop.ev_loop.get(),
                -1,
                0,
                [](evutil_socket_t, short, void* self) {
                    log::trace(log_cat, "processing job queue");
                    static_cast<JobQueue*>(self)->process_job_queue();
                },
                this));
        assert(job_waker);
    }

    // Ids are never negative; -1 is the default-constructed "no timer" value.  Process-wide rather
    // than per-queue so that an id from a dead or different queue is simply not found.
    static std::atomic<int64_t> next_timer_id{0};

    TimerID JobQueue::add_entry(std::chrono::microseconds interval, std::function<void()> f, bool one_shot)
    {
        if (!f)
            throw std::invalid_argument{"JobQueue: job callback must not be empty"};

        std::shared_ptr<Entry> e;
        TimerID id;
        {
            // The stopped check has to share a critical section with the insert to mean anything,
            // so build the entry in here too rather than constructing an event we may throw away.
            std::lock_guard lock{registry_mutex};
            if (registry_stopped)
                throw std::runtime_error{"Attempting to queue job onto stopped loop."};

            id = TimerID{next_timer_id++};

            e = std::shared_ptr<Entry>{new Entry{this, id, std::move(f), one_shot}, Entry::dispose};

            e->ev.reset(event_new(loop.get_event_base(), -1, EV_PERSIST, Entry::dispatch, e.get()));
            if (!e->ev)
                throw std::runtime_error{"JobQueue: failed to create job event"};

            registry.emplace(id, e);
        }

        // A one-shot always gets armed, even with a non-positive delay (libevent treats a zero
        // timeout as "next loop iteration"), because it is disposed of by firing; a timer
        // with no interval is simply left unarmed until something wakes or repeats it.
        if (one_shot or interval > 0us)
        {
            auto tv = loop_time_to_timeval(std::max(interval, 0us));
            event_add(e->ev.get(), &tv);
        }

        return id;
    }

    std::shared_ptr<JobQueue::Entry> JobQueue::find(TimerID id)
    {
        std::lock_guard lock{registry_mutex};
        if (auto it = registry.find(id); it != registry.end())
            return it->second;
        return nullptr;
    }

    void JobQueue::disarm(Entry& e)
    {
        // libevent stores the repeat interval in the event itself (ev_io_timeout) and event_del
        // does not clear it, so merely deleting leaves a timer that starts repeating again the
        // instant it is next wake()d, because the persist closure re-arms from that stored value.
        // Re-assigning with EV_PERSIST is what clears it.
        //
        // This event_del must stay blocking (i.e. not event_del_noblock): event_assign takes no base
        // lock, so the only thing stopping it racing the loop thread is that event_del has already
        // waited for any in-flight callback to finish.
        event_del(e.ev.get());
        event_assign(e.ev.get(), loop.get_event_base(), -1, EV_PERSIST, Entry::dispatch, &e);
    }

    void JobQueue::call_later(std::chrono::microseconds delay, std::function<void()> f)
    {
        add_entry(delay, std::move(f), true);
    }

    TimerID JobQueue::add_timer(std::chrono::microseconds interval, std::function<void()> f)
    {
        return add_entry(interval, std::move(f), false);
    }

    TimerID JobQueue::add_timer(std::function<void()> f)
    {
        return add_timer(0us, std::move(f));
    }

    TimerID JobQueue::add_wakeable(std::function<void()> f)
    {
        return add_timer(0us, std::move(f));
    }

    void JobQueue::wake(TimerID id)
    {
        auto e = find(id);
        if (!e)
            throw std::invalid_argument{"JobQueue::wake: no such job {}"_format(id)};

        event_active(e->ev.get(), 0, 0);
    }

    void JobQueue::repeat(TimerID id, std::chrono::microseconds interval, bool now)
    {
        auto e = find(id);
        if (!e)
            throw std::invalid_argument{"JobQueue::repeat: no such job {}"_format(id)};

        if (interval > 0us)
        {
            auto tv = loop_time_to_timeval(interval);
            event_add(e->ev.get(), &tv);
        }
        else
            disarm(*e);

        if (now)
            event_active(e->ev.get(), 0, 0);
    }

    bool JobQueue::armed(TimerID id)
    {
        auto e = find(id);
        return e and event_pending(e->ev.get(), EV_TIMEOUT, nullptr) != 0;
    }

    bool JobQueue::stop(TimerID id)
    {
        auto e = find(id);
        if (!e)
            return false;

        bool was_scheduled = event_pending(e->ev.get(), EV_TIMEOUT, nullptr) != 0;
        disarm(*e);
        return was_scheduled;
    }

    bool JobQueue::remove(TimerID id)
    {
        std::shared_ptr<Entry> e;
        {
            std::lock_guard lock{registry_mutex};
            auto it = registry.find(id);
            if (it == registry.end())
                return false;
            e = std::move(it->second);
            registry.erase(it);
        }

        // The registry lock *must* already be released here: called from off the loop thread,
        // event_del blocks until this timer's callback finishes, and that callback may itself want
        // the registry (to wake another timer, or to dispose of itself if it is a one-shot).
        event_del(e->ev.get());

        return true;
    }

    void JobQueue::process_job_queue()
    {
        log::trace(log_cat, "Event loop processing job queue");
        assert(inside());

        decltype(job_queue) swapped_queue;

        {
            std::lock_guard<std::mutex> lock{job_queue_mutex};
            job_queue.swap(swapped_queue);
        }

        // copy shared_ptr<bool> as a "running" canary, as this object's destructor
        // should eventually be one of the queued jobs, after which no further jobs
        // should run.
        auto running_ptr = running;

        while (not swapped_queue.empty() && *running_ptr)
        {
            auto job = swapped_queue.front();
            swapped_queue.pop();

            // We are inside a libevent callback, so an escaping exception would unwind through C
            // frames and terminate; one bad job also must not cost the rest of the queue its turn.
            try
            {
                job();
            }
            catch (const std::exception& e)
            {
                log::warning(log_cat, "Queued job raised an exception: {}", e.what());
            }
            catch (...)
            {
                log::warning(log_cat, "Queued job raised an unknown exception");
            }
        }
    }

    bool JobQueue::inside() const
    {
        return loop.inside();
    }

    // Wrapper around event_active so that we can keep libevent out of the public headers.
    void JobQueue::activate(::event& evt)
    {
        event_active(&evt, 0, 0);
    }

}  //  namespace oxen::quic
