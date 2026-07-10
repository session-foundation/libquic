#include "loop.hpp"

#include "internal.hpp"

#include <event2/event.h>
#include <event2/thread.h>

#include <fmt/ranges.h>

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
            log::warning(log_cat, "EventHandler failed to start repeating event!");
            return false;
        }

        return true;
    }

    bool Ticker::stop()
    {
        if (ev && event_del(ev.get()) != 0)
        {
            log::warning(log_cat, "EventHandler failed to pause repeating event!");
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

        if (static bool once = false; !once)
        {
            once = true;
            setup_libevent_logging();

            // Older versions of libevent do not like having this called multiple times
#ifdef _WIN32
            evthread_use_windows_threads();
#else
            evthread_use_pthreads();
#endif
        }

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

    struct JobQueue::OneShotDelayed
    {
        JobQueue& jq;
        std::function<void()> f;
        event_ptr ev;

        OneShotDelayed(JobQueue& jq_, std::function<void()> f) : jq{jq_}, f{std::move(f)} {}

        ~OneShotDelayed()
        {
            if (ev)
                event_del(ev.get());
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

        std::lock_guard l{job_queue_mutex};
        if (!job_waker)
            return;

        log::debug(log_cat, "Stopping/cancelling job queue events");
        *running = false;

        job_waker.reset();

        // Why does std::queue not have a clear() method?
        std::queue<Job>{}.swap(job_queue);

        for (auto* osd : delayed_events)
            delete osd;
        delayed_events.clear();
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

    void JobQueue::add_oneshot_event(std::chrono::microseconds delay, std::function<void()> hook)
    {
        // lock if not in loop thread, to make running check safe -- most uses of this should be
        // from the loop thread, so this shouldn't be a bottleneck
        std::unique_lock l{job_queue_mutex, std::defer_lock};
        if (!inside())
            l.lock();

        if (!*running)
            throw std::runtime_error{"Attempting to queue job onto stopped loop."};

        auto* handler = new OneShotDelayed{*this, std::move(hook)};
        delayed_events.push_back(handler);
        auto& h = *handler;
        const auto delay_tv = loop_time_to_timeval(delay);
        h.ev.reset(event_new(
                loop.get_event_base(),
                -1,
                0,
                [](evutil_socket_t, short, void* e) mutable {
                    auto* h = static_cast<OneShotDelayed*>(e);
                    if (h->f)
                        h->f();
                    auto& de = h->jq.delayed_events;
                    if (auto it = std::find(de.begin(), de.end(), h); it != de.end())
                        de.erase(it);
                    delete h;
                },
                &h));
        event_add(h.ev.get(), &delay_tv);
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
            job();
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
