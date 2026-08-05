// Guest threads.
//
// The emulator interprets one instruction stream at a time, so threads are
// cooperative: each gets a slice of instructions, and the scheduler switches at
// the end of a slice or the moment a thread blocks.  That is a legitimate
// implementation rather than a shortcut - a correct guest may not assume
// anything about how its threads interleave - and it keeps the emulator itself
// single-threaded, so nothing in it needs locking.
//
// What a thread owns is a full CPU context, its own stack, its own TEB, and its
// own copy of every module's static thread-local storage.  Getting that last
// part wrong is the classic way for threads to appear to work and then corrupt
// each other's data.
#include <cstring>
#include <memory>
#include <set>
#include <utility>
#include <string>
#include <vector>

#include "emulator.h"
#include "guest_printf.h"
#include "processes.h"

namespace x86emu {

namespace {
// Long enough that switching costs nothing measurable, short enough that a
// thread spinning on a flag another thread sets still makes progress.
constexpr uint64_t kQuantum = 20000;
constexpr uint64_t kInfinite = 0xFFFFFFFFull;
}  // namespace

uint32_t Emulator::current_thread_id() const {
    return threads_.empty() ? 1234 : threads_[current_thread_]->id;
}

Emulator::GuestThread* Emulator::current_thread() {
    return threads_.empty() ? nullptr : threads_[current_thread_].get();
}

// ---------------------------------------------------------------------------
// Context switching
// ---------------------------------------------------------------------------

void Emulator::switch_to_thread(size_t index) {
    if (index == current_thread_ && !threads_.empty()) return;

    if (!threads_.empty()) {
        GuestThread& out = *threads_[current_thread_];
        std::memcpy(out.regs, cpu_->regs, sizeof out.regs);
        std::memcpy(out.xmm, cpu_->xmm, sizeof out.xmm);
        std::memcpy(out.st, cpu_->st, sizeof out.st);
        std::memcpy(out.st_used, cpu_->st_used, sizeof out.st_used);
        out.st_top = cpu_->st_top;
        out.fpu_control = cpu_->fpu_control;
        out.fpu_status = cpu_->fpu_status;
        out.mxcsr = cpu_->mxcsr;
        out.rip = cpu_->rip;
        out.rflags = cpu_->rflags;
        out.fs_base = cpu_->fs_base;
        out.gs_base = cpu_->gs_base;
    }

    current_thread_ = index;
    GuestThread& in = *threads_[index];
    std::memcpy(cpu_->regs, in.regs, sizeof in.regs);
    std::memcpy(cpu_->xmm, in.xmm, sizeof in.xmm);
    std::memcpy(cpu_->st, in.st, sizeof in.st);
    std::memcpy(cpu_->st_used, in.st_used, sizeof in.st_used);
    cpu_->st_top = in.st_top;
    cpu_->fpu_control = in.fpu_control;
    cpu_->fpu_status = in.fpu_status;
    cpu_->mxcsr = in.mxcsr;
    cpu_->rip = in.rip;
    cpu_->rflags = in.rflags;
    cpu_->fs_base = in.fs_base;
    cpu_->gs_base = in.gs_base;
}

size_t Emulator::pick_runnable() {
    // Wake anything whose wait has been satisfied, then round-robin from just
    // after the current thread so no one starves.
    for (auto& t : threads_) {
        if (t->state != GuestThread::State::Blocked) continue;
        if (t->wake_at && cpu_->instructions_executed >= t->wake_at) {
            t->wake_at = 0;
            t->wait_handle = 0;
            t->wait_predicate = nullptr;
            t->state = GuestThread::State::Runnable;
            continue;
        }
        if (t->wait_handle && try_acquire(t->wait_handle)) {
            t->wait_handle = 0;
            t->wake_at = 0;
            t->wait_predicate = nullptr;
            t->state = GuestThread::State::Runnable;
            continue;
        }
        // The general wake condition: bytes arrived in a pipe, a child process
        // exited, a futex was woken - anything the scheduler can only ask about.
        if (t->wait_predicate && t->wait_predicate()) {
            t->wait_predicate = nullptr;
            t->wait_handle = 0;
            t->wake_at = 0;
            t->state = GuestThread::State::Runnable;
        }
    }

    for (size_t step = 1; step <= threads_.size(); ++step) {
        size_t i = (current_thread_ + step) % threads_.size();
        if (threads_[i]->state == GuestThread::State::Runnable) return i;
    }
    if (threads_[current_thread_]->state == GuestThread::State::Runnable)
        return current_thread_;
    return threads_.size();  // nothing can run
}

// ---------------------------------------------------------------------------
// Waitable objects
// ---------------------------------------------------------------------------

uint64_t Emulator::create_sync_object(SyncObject::Kind kind, bool manual_reset, bool signalled,
                                      int64_t count) {
    uint64_t handle = next_sync_handle_;
    next_sync_handle_ += 8;
    SyncObject o;
    o.kind = kind;
    o.manual_reset = manual_reset;
    o.signalled = signalled;
    o.count = count;
    sync_objects_[handle] = o;
    return handle;
}

Emulator::SyncObject* Emulator::sync_object(uint64_t handle) {
    auto it = sync_objects_.find(handle);
    return it == sync_objects_.end() ? nullptr : &it->second;
}

// Takes the object if it is available, applying whatever side effect that has:
// an auto-reset event clears, a semaphore decrements, a mutex records its owner.
bool Emulator::try_acquire(uint64_t handle) {
    SyncObject* o = sync_object(handle);
    if (!o) return true;  // an unknown handle is not something to wait on
    switch (o->kind) {
        case SyncObject::Kind::Event:
            if (!o->signalled) return false;
            if (!o->manual_reset) o->signalled = false;
            return true;
        case SyncObject::Kind::Semaphore:
            if (o->count <= 0) return false;
            --o->count;
            return true;
        case SyncObject::Kind::Mutex: {
            uint32_t me = current_thread_id();
            if (o->owner == 0 || o->owner == me) {
                o->owner = me;
                ++o->recursion;
                return true;
            }
            return false;
        }
        case SyncObject::Kind::Process:
            // The System is the authority on whether the child has finished;
            // asking it every time keeps the handle from needing notification.
            return o->signalled ||
                   (system_ && system_->is_zombie(static_cast<int>(o->owner)));
        default:  // Thread: signalled once it has finished
            return o->signalled;
    }
}

void Emulator::signal_object(uint64_t handle) {
    SyncObject* o = sync_object(handle);
    if (o) o->signalled = true;
}

bool Emulator::begin_wait(uint64_t handle, uint64_t timeout_ms) {
    if (try_acquire(handle)) return true;   // available now, no need to block
    if (timeout_ms == 0) return false;      // a zero timeout is a poll

    GuestThread* t = current_thread();
    if (!t) return false;
    t->state = GuestThread::State::Blocked;
    t->wait_handle = handle;
    // Time is measured in instructions here, so a millisecond is a made-up but
    // consistent number of them.
    t->wake_at = timeout_ms == kInfinite ? 0 : cpu_->instructions_executed + timeout_ms * 1000;
    yield_now();
    return false;
}

// ---------------------------------------------------------------------------
// Creating and ending threads
// ---------------------------------------------------------------------------

uint64_t Emulator::allocate_thread_tls(uint64_t teb) {
    // Every module's static TLS is per-thread, so a new thread gets its own copy
    // of each template rather than sharing the main thread's block.
    uint64_t array = heap_alloc(4096);
    if (!array) return 0;
    std::vector<uint8_t> zeros(4096, 0);
    mem.write(array, zeros.data(), zeros.size());

    for (const auto& t : tls_templates_) {
        uint64_t block = heap_alloc(t.total_size);
        if (!block) continue;
        std::vector<uint8_t> bytes(static_cast<size_t>(t.total_size), 0);
        if (t.template_size) mem.read(t.source, bytes.data(), t.template_size);
        mem.write(block, bytes.data(), bytes.size());
        mem.write_sized(array + static_cast<uint64_t>(t.slot) * pointer_size(), pointer_size(),
                        block);
    }
    // The TEB points at the array; that indirection is what gs:[0x58] reads.
    if (teb) mem.write_sized(teb + (is64() ? 0x58 : 0x2C), pointer_size(), array);
    return array;
}

uint64_t Emulator::create_thread(uint64_t start, uint64_t argument, uint64_t stack_size) {
    if (stack_size == 0) stack_size = 1ull << 20;
    stack_size = (stack_size + 0xFFFF) & ~0xFFFFull;

    auto t = std::make_unique<GuestThread>();
    t->id = next_thread_id_++;
    t->stack_size = stack_size;
    t->stack_base = alloc_pages(stack_size);
    if (!t->stack_base) return 0;

    // Its own TEB, so that stack bounds and thread id are the thread's own.
    std::vector<uint8_t> teb_bytes(0x1000, 0);
    t->teb = alloc_guest_data(teb_bytes.data(), teb_bytes.size());
    uint64_t stack_top = t->stack_base + stack_size;
    if (is64()) {
        mem.write64(t->teb + 0x08, stack_top);
        mem.write64(t->teb + 0x10, t->stack_base);
        mem.write64(t->teb + 0x30, t->teb);   // Self
        mem.write64(t->teb + 0x48, t->id);    // ClientId.UniqueThread
        mem.write64(t->teb + 0x60, mem.read64(threads_[0]->teb + 0x60));  // the shared PEB
        t->gs_base = t->teb;
    } else {
        mem.write32(t->teb + 0x00, 0xFFFFFFFFu);  // SEH chain: end of list
        mem.write32(t->teb + 0x04, static_cast<uint32_t>(stack_top));
        mem.write32(t->teb + 0x08, static_cast<uint32_t>(t->stack_base));
        mem.write32(t->teb + 0x18, static_cast<uint32_t>(t->teb));
        mem.write32(t->teb + 0x24, t->id);
        mem.write32(t->teb + 0x30, mem.read32(threads_[0]->teb + 0x30));
        t->fs_base = t->teb;
    }
    t->tls_array = allocate_thread_tls(t->teb);

    // The initial context: the start routine, its one argument, and a return
    // address that ends the thread.
    uint64_t rsp = (stack_top - 0x1000) & ~0xFull;
    switch (abi()) {
        case Abi::Cdecl32:
            rsp = (rsp - 4) & ~0xFull;
            mem.write32(rsp, static_cast<uint32_t>(argument));
            break;
        case Abi::MsX64:
            rsp = (rsp - 32) & ~0xFull;  // shadow space for the callee
            t->regs[RCX] = argument;
            break;
        default:
            t->regs[RDI] = argument;
            break;
    }
    rsp -= pointer_size();
    mem.write_sized(rsp, pointer_size(), thread_exit_thunk_);
    t->regs[RSP] = rsp;
    t->rip = start;
    t->rflags = 0x202;

    // A thread is a waitable object; joining it is waiting for that object.
    t->handle = create_sync_object(SyncObject::Kind::Thread, true, false, 0);
    sync_object(t->handle)->owner = t->id;

    log_call("create_thread %u at 0x%llX, stack 0x%llX", t->id, (unsigned long long)start,
             (unsigned long long)t->stack_base);
    threads_.push_back(std::move(t));
    return threads_.back()->handle;
}

uint32_t Emulator::clone_thread(uint64_t stack, uint64_t tls, uint64_t clear_child_tid) {
    auto t = std::make_unique<GuestThread>();
    t->id = next_thread_id_++;
    t->clear_child_tid = clear_child_tid;

    // The child is the calling context verbatim - same RIP (already past the
    // syscall instruction), the caller-provided stack, its own TLS base - with
    // RAX zeroed, which is how the guest's clone() wrapper tells the two apart.
    std::memcpy(t->regs, cpu_->regs, sizeof t->regs);
    std::memcpy(t->xmm, cpu_->xmm, sizeof t->xmm);
    std::memcpy(t->st, cpu_->st, sizeof t->st);
    std::memcpy(t->st_used, cpu_->st_used, sizeof t->st_used);
    t->st_top = cpu_->st_top;
    t->fpu_control = cpu_->fpu_control;
    t->fpu_status = cpu_->fpu_status;
    t->mxcsr = cpu_->mxcsr;
    t->rip = cpu_->rip;
    t->rflags = cpu_->rflags;
    t->fs_base = tls ? tls : cpu_->fs_base;
    t->gs_base = cpu_->gs_base;
    t->regs[RAX] = 0;
    if (stack) t->regs[RSP] = stack;

    t->handle = create_sync_object(SyncObject::Kind::Thread, true, false, 0);
    sync_object(t->handle)->owner = t->id;
    log_call("clone_thread %u, stack 0x%llX, tls 0x%llX", t->id, (unsigned long long)stack,
             (unsigned long long)tls);
    threads_.push_back(std::move(t));
    return threads_.back()->id;
}

void Emulator::exit_thread(uint32_t exit_code) {
    GuestThread* t = current_thread();
    if (!t) {
        exit_process(static_cast<int>(exit_code));
        return;
    }
    t->exit_code = exit_code;
    t->state = GuestThread::State::Finished;
    signal_object(t->handle);
    // The process ends when its first thread does, as on Windows.
    if (current_thread_ == 0) exit_process(static_cast<int>(exit_code));
    yield_now();
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

void Emulator::install_thread_hooks() {
    auto win32 = [this](const char* name, int nargs, std::function<void(Emulator&)> fn) {
        add_hook(name, is64() ? 0 : nargs * 4, std::move(fn));
    };

    // Reaching this address means a thread's start routine returned.
    thread_exit_thunk_ = add_hook("__emu_thread_exit__", 0, [](Emulator& e) {
        e.exit_thread(static_cast<uint32_t>(e.cpu().regs[RAX]));
    });

    // (attributes, stack size, start, parameter, flags, out thread id)
    win32("CreateThread", 6, [](Emulator& e) {
        uint64_t handle = e.create_thread(e.arg_slot(2), e.arg_slot(3), e.arg_slot(1));
        if (handle && e.arg_slot(5)) {
            auto* o = e.sync_object(handle);
            e.mem.write32(e.arg_slot(5), o ? o->owner : 0);
        }
        e.set_result(handle);
    });
    // The CRT's wrapper has the same shape with different argument order.
    add_hook("_beginthreadex", 0, [](Emulator& e) {
        uint64_t handle = e.create_thread(e.arg_slot(2), e.arg_slot(3), e.arg_slot(1));
        if (handle && e.arg_slot(5)) {
            auto* o = e.sync_object(handle);
            e.mem.write32(e.arg_slot(5), o ? o->owner : 0);
        }
        e.set_result(handle);
    });
    add_hook("_beginthread", 0, [](Emulator& e) {
        e.set_result(e.create_thread(e.arg_slot(0), e.arg_slot(2), e.arg_slot(1)));
    });
    win32("ExitThread", 1, [](Emulator& e) {
        e.exit_thread(static_cast<uint32_t>(e.arg_slot(0)));
    });
    add_hook("_endthreadex", 0, [](Emulator& e) {
        e.exit_thread(static_cast<uint32_t>(e.arg_slot(0)));
    });
    add_hook("_endthread", 0, [](Emulator& e) { e.exit_thread(0); });
    win32("GetCurrentThreadId", 0, [](Emulator& e) { e.set_result(e.current_thread_id()); });
    win32("GetExitCodeThread", 2, [](Emulator& e) {
        auto* o = e.sync_object(e.arg_slot(0));
        uint32_t code = 259;  // STILL_ACTIVE
        if (o) {
            for (const auto& t : e.threads())
                if (t->handle == e.arg_slot(0) &&
                    t->state == GuestThread::State::Finished)
                    code = t->exit_code;
        }
        if (e.arg_slot(1)) e.mem.write32(e.arg_slot(1), code);
        e.set_result(1);
    });
    win32("SwitchToThread", 0, [](Emulator& e) {
        e.yield_now();
        e.set_result(1);
    });
    win32("Sleep", 1, [](Emulator& e) {
        uint64_t ms = e.arg_slot(0);
        GuestThread* t = e.current_thread();
        if (t && ms) {
            t->state = GuestThread::State::Blocked;
            t->wake_at = e.cpu().instructions_executed + ms * 1000;
        }
        e.yield_now();
        e.set_result(0);
    });
    win32("SleepEx", 2, [](Emulator& e) {
        e.yield_now();
        e.set_result(0);
    });
    win32("SwitchToFiber", 1, [](Emulator& e) { e.set_result(0); });
    win32("TerminateThread", 2, [](Emulator& e) { e.set_result(1); });
    win32("ResumeThread", 1, [](Emulator& e) { e.set_result(1); });
    win32("SuspendThread", 1, [](Emulator& e) { e.set_result(0); });

    // ---- waiting -----------------------------------------------------------
    win32("WaitForSingleObject", 2, [](Emulator& e) {
        uint64_t handle = e.arg_slot(0), timeout = e.arg_slot(1);
        if (e.begin_wait(handle, timeout)) {
            e.set_result(0);  // WAIT_OBJECT_0
        } else {
            // Either the thread is now blocked and will retry when it next runs,
            // or the timeout was zero and this is the answer.
            e.set_result(timeout == 0 ? 0x102u /* WAIT_TIMEOUT */ : 0u);
        }
    });
    win32("WaitForSingleObjectEx", 3, [](Emulator& e) {
        if (e.begin_wait(e.arg_slot(0), e.arg_slot(1)))
            e.set_result(0);
        else
            e.set_result(e.arg_slot(1) == 0 ? 0x102u : 0u);
    });
    win32("WaitForMultipleObjects", 4, [](Emulator& e) {
        // (count, handles, wait_all, timeout)
        uint64_t count = e.arg_slot(0), handles = e.arg_slot(1);
        bool wait_all = e.arg_slot(2) != 0;
        int ps = e.pointer_size();
        if (!wait_all) {
            for (uint64_t i = 0; i < count; ++i) {
                uint64_t h = e.mem.read_sized(handles + i * ps, ps);
                if (e.try_acquire(h)) {
                    e.set_result(i);  // WAIT_OBJECT_0 + i
                    return;
                }
            }
            // Block on the first; the retry will look at all of them again.
            if (count) e.begin_wait(e.mem.read_sized(handles, ps), e.arg_slot(3));
            e.set_result(0);
            return;
        }
        for (uint64_t i = 0; i < count; ++i) {
            uint64_t h = e.mem.read_sized(handles + i * ps, ps);
            if (!e.begin_wait(h, e.arg_slot(3))) {
                e.set_result(0);
                return;
            }
        }
        e.set_result(0);
    });

    // ---- events, mutexes and semaphores --------------------------------------
    // ---- named kernel objects --------------------------------------------------
    // Every Create/Open pair below shares two helpers so that a name behaves the
    // way the guest expects: creating twice under one name yields one object and
    // ERROR_ALREADY_EXISTS, and opening a name nobody created fails.
    auto object_name = [](Emulator& e, int slot, bool wide) -> std::string {
        uint64_t p = e.arg_slot(slot);
        if (!p) return {};
        return wide ? utf16_to_utf8(e, p, -1) : e.mem.read_cstring(p);
    };
    auto create_named = [object_name](Emulator& e, int name_slot, bool wide,
                                     SyncObject::Kind kind, bool manual_reset,
                                     bool signalled, int64_t count) -> uint64_t {
        std::string name = object_name(e, name_slot, wide);
        if (!name.empty()) {
            if (uint64_t* existing = e.named_object(name)) {
                e.set_last_error(183);  // ERROR_ALREADY_EXISTS
                e.set_result(*existing);
                return *existing;
            }
        }
        uint64_t h = e.create_sync_object(kind, manual_reset, signalled, count);
        if (!name.empty()) e.name_object(name, h);
        e.set_result(h);
        return h;
    };
    // OpenXxx(access, inherit, name): the name is the whole request, so an
    // unknown one is a failure and not something to paper over.
    auto open_named = [object_name](Emulator& e, bool wide, SyncObject::Kind kind) {
        std::string name = object_name(e, 2, wide);
        uint64_t* existing = name.empty() ? nullptr : e.named_object(name);
        if (!existing || !e.sync_object(*existing) ||
            e.sync_object(*existing)->kind != kind) {
            e.set_last_error(2);  // ERROR_FILE_NOT_FOUND
            e.set_result(0);
            return;
        }
        e.set_result(*existing);
    };

    // CreateEvent(attributes, manual_reset, initial_state, name)
    win32("CreateEventA", 4, [create_named](Emulator& e) {
        create_named(e, 3, false, SyncObject::Kind::Event, e.arg_slot(1) != 0,
                     e.arg_slot(2) != 0, 0);
    });
    win32("CreateEventW", 4, [create_named](Emulator& e) {
        create_named(e, 3, true, SyncObject::Kind::Event, e.arg_slot(1) != 0,
                     e.arg_slot(2) != 0, 0);
    });
    win32("CreateEventExW", 4, [create_named](Emulator& e) {
        // (attributes, name, flags, access); flags bit 1 is CREATE_EVENT_MANUAL_RESET
        uint64_t flags = e.arg_slot(2);
        create_named(e, 1, true, SyncObject::Kind::Event, (flags & 1) != 0,
                     (flags & 2) != 0, 0);
    });
    win32("OpenEventA", 3, [open_named](Emulator& e) {
        open_named(e, false, SyncObject::Kind::Event);
    });
    win32("OpenEventW", 3, [open_named](Emulator& e) {
        open_named(e, true, SyncObject::Kind::Event);
    });
    win32("SetEvent", 1, [](Emulator& e) {
        e.signal_object(e.arg_slot(0));
        e.set_result(1);
    });
    win32("ResetEvent", 1, [](Emulator& e) {
        auto* o = e.sync_object(e.arg_slot(0));
        if (o) o->signalled = false;
        e.set_result(1);
    });
    win32("PulseEvent", 1, [](Emulator& e) {
        e.signal_object(e.arg_slot(0));
        e.set_result(1);
    });
    // CreateMutex(attributes, initial_owner, name)
    auto create_mutex = [create_named](Emulator& e, bool wide) {
        uint64_t h = create_named(e, 2, wide, SyncObject::Kind::Mutex, false, false, 0);
        if (e.arg_slot(1)) e.try_acquire(h);  // bInitialOwner
    };
    win32("CreateMutexA", 3, [create_mutex](Emulator& e) { create_mutex(e, false); });
    win32("CreateMutexW", 3, [create_mutex](Emulator& e) { create_mutex(e, true); });
    win32("CreateMutexExW", 4, [create_named](Emulator& e) {
        // (attributes, name, flags, access); flags bit 0 asks for initial ownership
        uint64_t h = create_named(e, 1, true, SyncObject::Kind::Mutex, false, false, 0);
        if (e.arg_slot(2) & 1) e.try_acquire(h);
    });
    win32("OpenMutexA", 3, [open_named](Emulator& e) {
        open_named(e, false, SyncObject::Kind::Mutex);
    });
    win32("OpenMutexW", 3, [open_named](Emulator& e) {
        open_named(e, true, SyncObject::Kind::Mutex);
    });
    win32("ReleaseMutex", 1, [](Emulator& e) {
        auto* o = e.sync_object(e.arg_slot(0));
        if (o && --o->recursion <= 0) {
            o->recursion = 0;
            o->owner = 0;
        }
        e.set_result(1);
    });
    // CreateSemaphore(attributes, initial count, maximum count, name); the Ex
    // form adds flags and access after the name, which changes nothing here.
    auto create_semaphore = [create_named](Emulator& e, bool wide) {
        create_named(e, 3, wide, SyncObject::Kind::Semaphore, false, false,
                     static_cast<int64_t>(e.arg_slot(1)));
    };
    win32("CreateSemaphoreA", 4, [create_semaphore](Emulator& e) {
        create_semaphore(e, false);
    });
    win32("CreateSemaphoreW", 4, [create_semaphore](Emulator& e) {
        create_semaphore(e, true);
    });
    win32("CreateSemaphoreExW", 6, [create_semaphore](Emulator& e) {
        create_semaphore(e, true);
    });
    win32("OpenSemaphoreA", 3, [open_named](Emulator& e) {
        open_named(e, false, SyncObject::Kind::Semaphore);
    });
    win32("OpenSemaphoreW", 3, [open_named](Emulator& e) {
        open_named(e, true, SyncObject::Kind::Semaphore);
    });
    win32("ReleaseSemaphore", 3, [](Emulator& e) {
        auto* o = e.sync_object(e.arg_slot(0));
        if (o) {
            if (e.arg_slot(2)) e.mem.write32(e.arg_slot(2), static_cast<uint32_t>(o->count));
            o->count += static_cast<int64_t>(e.arg_slot(1));
        }
        e.set_result(1);
    });

    // ---- critical sections and slim locks -------------------------------------
    // Both are objects the caller owns, so the lock state lives in guest memory:
    // the first pointer-sized word holds the owning thread id, the second the
    // recursion count.  That keeps them per-object without a table.
    win32("InitializeCriticalSection", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) {
            e.mem.write_sized(p, e.pointer_size(), 0);
            e.mem.write_sized(p + e.pointer_size(), e.pointer_size(), 0);
        }
        e.set_result(0);
    });
    win32("InitializeCriticalSectionAndSpinCount", 2, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) {
            e.mem.write_sized(p, e.pointer_size(), 0);
            e.mem.write_sized(p + e.pointer_size(), e.pointer_size(), 0);
        }
        e.set_result(1);
    });
    win32("InitializeCriticalSectionEx", 3, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        if (p) {
            e.mem.write_sized(p, e.pointer_size(), 0);
            e.mem.write_sized(p + e.pointer_size(), e.pointer_size(), 0);
        }
        e.set_result(1);
    });
    auto enter_lock = [](Emulator& e, uint64_t p, bool blocking) -> bool {
        if (!p) return true;
        int ps = e.pointer_size();
        uint64_t owner = e.mem.read_sized(p, ps);
        uint32_t me = e.current_thread_id();
        if (owner == 0 || owner == me) {
            e.mem.write_sized(p, ps, me);
            e.mem.write_sized(p + ps, ps, e.mem.read_sized(p + ps, ps) + 1);
            return true;
        }
        if (blocking) {
            // Held by another thread: give up the slice.  The caller arranges for
            // the same call to happen again once this thread runs next.
            e.yield_now();
        }
        return false;
    };
    win32("EnterCriticalSection", 1, [enter_lock](Emulator& e) {
        if (!enter_lock(e, e.arg_slot(0), true)) {
            // Rewind so the guest calls this again after the switch.
            e.retry_current_call();
        }
        e.set_result(0);
    });
    win32("TryEnterCriticalSection", 1, [enter_lock](Emulator& e) {
        e.set_result(enter_lock(e, e.arg_slot(0), false) ? 1 : 0);
    });
    win32("LeaveCriticalSection", 1, [](Emulator& e) {
        uint64_t p = e.arg_slot(0);
        int ps = e.pointer_size();
        if (p) {
            uint64_t depth = e.mem.read_sized(p + ps, ps);
            if (depth > 0) e.mem.write_sized(p + ps, ps, depth - 1);
            if (depth <= 1) e.mem.write_sized(p, ps, 0);
        }
        e.set_result(0);
    });
    win32("DeleteCriticalSection", 1, [](Emulator& e) { e.set_result(0); });

    // An SRWLOCK is exactly one pointer-sized word, and `SRWLOCK_INIT` is a zero
    // in guest memory - a guest may never call InitializeSRWLock at all.  So
    // everything has to fit in that one word, with zero meaning free:
    //
    //     0                       unheld
    //     (thread id << 1) | 1    held exclusively by that thread
    //     reader count << 1       held shared by that many readers
    //
    // The earlier version kept a recursion count in the *next* word, which is
    // past the end of the object.  For a statically initialised lock that word
    // held whatever the guest had put there, so the release path decremented a
    // large number, never reached zero, and never cleared the owner - after
    // which every other thread spun on the lock forever.  cl.exe's back end
    // found this by hanging in exactly that loop.
    win32("InitializeSRWLock", 1, [](Emulator& e) {
        if (e.arg_slot(0)) e.mem.write_sized(e.arg_slot(0), e.pointer_size(), 0);
        e.set_result(0);
    });
    auto take_srw = [](Emulator& e, uint64_t p, bool exclusive) -> bool {
        if (!p) return true;
        int ps = e.pointer_size();
        uint64_t word = e.mem.read_sized(p, ps);
        if (exclusive) {
            // SRW locks are not recursive; a guest that re-enters one deadlocks
            // on real Windows too, so there is nothing to be gained by allowing it.
            if (word != 0) return false;
            e.mem.write_sized(p, ps, (uint64_t(e.current_thread_id()) << 1) | 1);
            return true;
        }
        if (word & 1) return false;  // an exclusive holder blocks readers
        e.mem.write_sized(p, ps, word + 2);
        return true;
    };
    auto acquire_srw = [take_srw](Emulator& e, bool exclusive) {
        if (!take_srw(e, e.arg_slot(0), exclusive)) {
            // Held: give up the slice and arrange for the same call to happen
            // again the next time this thread runs.
            e.yield_now();
            e.retry_current_call();
        }
        e.set_result(0);
    };
    win32("AcquireSRWLockExclusive", 1,
          [acquire_srw](Emulator& e) { acquire_srw(e, true); });
    win32("AcquireSRWLockShared", 1,
          [acquire_srw](Emulator& e) { acquire_srw(e, false); });
    auto release_srw = [](Emulator& e, bool exclusive) {
        uint64_t p = e.arg_slot(0);
        if (p) {
            int ps = e.pointer_size();
            uint64_t word = e.mem.read_sized(p, ps);
            if (exclusive || (word & 1) || word <= 2)
                e.mem.write_sized(p, ps, 0);
            else
                e.mem.write_sized(p, ps, word - 2);
        }
        e.set_result(0);
    };
    win32("ReleaseSRWLockExclusive", 1,
          [release_srw](Emulator& e) { release_srw(e, true); });
    win32("ReleaseSRWLockShared", 1,
          [release_srw](Emulator& e) { release_srw(e, false); });
    win32("TryAcquireSRWLockExclusive", 1, [take_srw](Emulator& e) {
        e.set_result(take_srw(e, e.arg_slot(0), true) ? 1 : 0);
    });
    win32("TryAcquireSRWLockShared", 1, [take_srw](Emulator& e) {
        e.set_result(take_srw(e, e.arg_slot(0), false) ? 1 : 0);
    });

    // A condition variable is a pointer-sized object the caller owns.  With
    // cooperative threads the wake operations have nothing to do: a waiter always
    // re-checks its predicate after yielding.
    win32("InitializeConditionVariable", 1, [](Emulator& e) {
        if (e.arg_slot(0)) e.mem.write_sized(e.arg_slot(0), e.pointer_size(), 0);
        e.set_result(0);
    });
    win32("WakeConditionVariable", 1, [](Emulator& e) { e.set_result(0); });
    win32("WakeAllConditionVariable", 1, [](Emulator& e) { e.set_result(0); });
    win32("InterlockedFlushSList", 1, [](Emulator& e) { e.set_result(0); });
    win32("CreateWaitableTimerExW", 4, [](Emulator& e) {
        e.set_result(e.create_sync_object(SyncObject::Kind::Event, true, false, 0));
    });
    win32("SetWaitableTimerEx", 6, [](Emulator& e) {
        // Nothing measures wall-clock time here, so a timer that is immediately
        // signalled is the closest honest behaviour.
        e.signal_object(e.arg_slot(0));
        e.set_result(1);
    });
    win32("CancelWaitableTimer", 1, [](Emulator& e) { e.set_result(1); });

    // A condition variable wait must drop its lock, let other threads run, and
    // then hold the lock again on return - the caller's predicate loop depends on
    // both halves.  Dropping it and returning immediately would leave the guest
    // thinking it owns a lock the word says is free, so the wait happens in two
    // visits to this hook: the first releases and yields, the second re-takes.
    // `sleeping` remembers which visit we are on; it is per emulator because
    // install_thread_hooks() runs once per process.
    auto sleeping = std::make_shared<std::set<std::pair<uint32_t, uint64_t>>>();
    win32("SleepConditionVariableSRW", 4, [sleeping, take_srw](Emulator& e) {
        uint64_t cv = e.arg_slot(0), lock = e.arg_slot(1);
        bool exclusive = (e.arg_slot(3) & 1) == 0;  // ..._LOCKMODE_SHARED
        std::pair<uint32_t, uint64_t> key{e.current_thread_id(), cv};
        e.set_result(1);
        if (!sleeping->count(key)) {
            if (lock) e.mem.write_sized(lock, e.pointer_size(), 0);
            sleeping->insert(key);
            e.yield_now();
            e.retry_current_call();
            return;
        }
        if (!take_srw(e, lock, exclusive)) {
            e.yield_now();
            e.retry_current_call();
            return;
        }
        sleeping->erase(key);
    });
    win32("SleepConditionVariableCS", 3, [sleeping, enter_lock](Emulator& e) {
        uint64_t cv = e.arg_slot(0), lock = e.arg_slot(1);
        std::pair<uint32_t, uint64_t> key{e.current_thread_id(), cv};
        int ps = e.pointer_size();
        e.set_result(1);
        if (!sleeping->count(key)) {
            if (lock) {
                e.mem.write_sized(lock, ps, 0);
                e.mem.write_sized(lock + ps, ps, 0);
            }
            sleeping->insert(key);
            e.yield_now();
            e.retry_current_call();
            return;
        }
        if (!enter_lock(e, lock, true)) {
            e.retry_current_call();
            return;
        }
        sleeping->erase(key);
    });
}

}  // namespace x86emu
