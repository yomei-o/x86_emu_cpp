// Structured and C++ exception handling on x86-64.
//
// There is no frame-pointer chain to walk on x64: unwinding is a table lookup.
// Every function has a RUNTIME_FUNCTION entry in the image's exception
// directory naming its UNWIND_INFO, and that describes the prologue as a short
// program - "pushed rbx, allocated 0x40, established rbp" - which run backwards
// recovers the caller's registers.  That is the whole mechanism, and it is why
// throwing needs the loader, the interpreter and the guest's own runtime to
// cooperate:
//
//   the guest throws            -> RaiseException (here)
//   we walk frames              -> RtlLookupFunctionEntry + RtlVirtualUnwind (here)
//   we call each language handler -> __CxxFrameHandler4 / __C_specific_handler,
//                                  which is *guest* code, statically linked
//   a handler accepts           -> it calls RtlUnwindEx (here), which runs the
//                                  intervening frames' destructors and jumps to
//                                  the catch
//
// So the emulator supplies the kernel's half and the guest supplies the
// language's half, exactly as on real Windows.  The context lives in guest
// memory throughout, because the guest passes CONTEXT pointers to its handlers
// and reads them back.
#include <cstring>
#include <string>
#include <vector>

#include "emulator.h"

namespace x86emu {
namespace {

// ---- CONTEXT (x64) ---------------------------------------------------------
// Only the fields a handler touches are modelled; the rest stays zero.  The
// integer registers happen to sit in the same order as this emulator's Reg
// enum, so one loop copies them.
constexpr uint64_t kContextSize = 1232;
constexpr uint64_t kOffContextFlags = 0x30;
constexpr uint64_t kOffMxCsr = 0x34;
constexpr uint64_t kOffSegCs = 0x38;
constexpr uint64_t kOffSegSs = 0x42;
constexpr uint64_t kOffEFlags = 0x44;
constexpr uint64_t kOffRegs = 0x78;   // Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8..R15
constexpr uint64_t kOffRip = 0xF8;
constexpr uint64_t kOffXmm = 0x1A0;   // FltSave.XmmRegisters
constexpr uint32_t kContextAll = 0x0010000B;  // CONTEXT_FULL | CONTEXT_SEGMENTS

// ---- EXCEPTION_RECORD ------------------------------------------------------
constexpr uint64_t kRecordSize = 152;
constexpr uint64_t kOffCode = 0x00;
constexpr uint64_t kOffFlags = 0x04;
constexpr uint64_t kOffNested = 0x08;
constexpr uint64_t kOffAddress = 0x10;
constexpr uint64_t kOffNumParams = 0x18;
constexpr uint64_t kOffParams = 0x20;

// ---- DISPATCHER_CONTEXT ----------------------------------------------------
constexpr uint64_t kDispatcherSize = 0x50;

constexpr uint32_t kExceptionNoncontinuable = 0x01;
constexpr uint32_t kExceptionUnwinding = 0x02;
constexpr uint32_t kExceptionExitUnwind = 0x04;
constexpr uint32_t kExceptionTargetUnwind = 0x20;
constexpr uint32_t kExceptionCollidedUnwind = 0x40;

// EXCEPTION_DISPOSITION
constexpr uint64_t kContinueExecution = 0;
constexpr uint64_t kContinueSearch = 1;
constexpr uint64_t kCollidedUnwind = 3;

constexpr uint32_t kUnwFlagEhandler = 1;
constexpr uint32_t kUnwFlagUhandler = 2;
constexpr uint32_t kUnwFlagChaininfo = 4;

constexpr uint32_t kStatusUnwind = 0xC0000027;
// The mechanism that actually runs a C++ catch block on x64.  A language
// runtime that wants code to execute *after* the stack has been unwound but
// *before* control resumes raises this code from the unwinder: parameter 0 is a
// callback, and whatever address it returns is where execution continues.
// MSVC's __CxxCallCatchBlock is that callback - it invokes the catch funclet and
// reports where the function should carry on afterwards.
constexpr uint32_t kStatusUnwindConsolidate = 0x80000029;

// Saves the running CPU state into a guest CONTEXT.
void capture_context(Emulator& e, uint64_t ctx) {
    std::vector<uint8_t> zeros(static_cast<size_t>(kContextSize), 0);
    e.mem.write(ctx, zeros.data(), zeros.size());
    e.mem.write32(ctx + kOffContextFlags, kContextAll);
    e.mem.write32(ctx + kOffMxCsr, e.cpu().mxcsr);
    e.mem.write16(ctx + kOffSegCs, 0x33);   // what a 64-bit user process really has
    e.mem.write16(ctx + kOffSegSs, 0x2B);
    e.mem.write32(ctx + kOffEFlags, static_cast<uint32_t>(e.cpu().rflags));
    for (int i = 0; i < 16; ++i)
        e.mem.write64(ctx + kOffRegs + static_cast<uint64_t>(i) * 8, e.cpu().regs[i]);
    e.mem.write64(ctx + kOffRip, e.cpu().rip);
    for (int i = 0; i < 16; ++i) {
        e.mem.write64(ctx + kOffXmm + static_cast<uint64_t>(i) * 16, e.cpu().xmm[i].q[0]);
        e.mem.write64(ctx + kOffXmm + static_cast<uint64_t>(i) * 16 + 8, e.cpu().xmm[i].q[1]);
    }
}

// Makes a guest CONTEXT the running state.  Used to resume at a catch block.
void restore_context(Emulator& e, uint64_t ctx) {
    for (int i = 0; i < 16; ++i)
        e.cpu().regs[i] = e.mem.read64(ctx + kOffRegs + static_cast<uint64_t>(i) * 8);
    e.cpu().rip = e.mem.read64(ctx + kOffRip);
    e.cpu().rflags = (e.cpu().rflags & ~0xFFFFFFFFull) | e.mem.read32(ctx + kOffEFlags);
    e.cpu().mxcsr = e.mem.read32(ctx + kOffMxCsr);
    for (int i = 0; i < 16; ++i) {
        e.cpu().xmm[i].q[0] = e.mem.read64(ctx + kOffXmm + static_cast<uint64_t>(i) * 16);
        e.cpu().xmm[i].q[1] = e.mem.read64(ctx + kOffXmm + static_cast<uint64_t>(i) * 16 + 8);
    }
}

uint64_t ctx_reg(Emulator& e, uint64_t ctx, int reg) {
    return e.mem.read64(ctx + kOffRegs + static_cast<uint64_t>(reg) * 8);
}
void set_ctx_reg(Emulator& e, uint64_t ctx, int reg, uint64_t v) {
    e.mem.write64(ctx + kOffRegs + static_cast<uint64_t>(reg) * 8, v);
}
uint64_t ctx_rip(Emulator& e, uint64_t ctx) { return e.mem.read64(ctx + kOffRip); }
void set_ctx_rip(Emulator& e, uint64_t ctx, uint64_t v) { e.mem.write64(ctx + kOffRip, v); }
uint64_t ctx_rsp(Emulator& e, uint64_t ctx) { return ctx_reg(e, ctx, RSP); }
void set_ctx_rsp(Emulator& e, uint64_t ctx, uint64_t v) { set_ctx_reg(e, ctx, RSP, v); }

// The unwind codes' register numbering is the classic encoding order, which is
// this emulator's Reg order too.
int unwind_reg(uint8_t op_info) { return op_info & 0xF; }

}  // namespace

// ---------------------------------------------------------------------------
// The function table
// ---------------------------------------------------------------------------

bool Emulator::lookup_function_entry(uint64_t pc, uint64_t& image_base, uint64_t& entry) {
    Module* m = module_for(pc);
    if (!m || !m->image.exception_table || !m->image.exception_table_size) return false;
    image_base = m->image.base;

    // The table is sorted by BeginAddress, so a binary search is both correct
    // and what makes throwing from a large image affordable.
    uint64_t table = m->image.exception_table;
    uint32_t count = m->image.exception_table_size / 12;
    uint32_t rva = static_cast<uint32_t>(pc - image_base);
    uint32_t lo = 0, hi = count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint64_t rec = table + static_cast<uint64_t>(mid) * 12;
        uint32_t begin = mem.read32(rec);
        uint32_t end = mem.read32(rec + 4);
        if (rva < begin) {
            hi = mid;
        } else if (rva >= end) {
            lo = mid + 1;
        } else {
            entry = rec;
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// RtlVirtualUnwind: one frame's worth of undoing a prologue
// ---------------------------------------------------------------------------

uint64_t Emulator::virtual_unwind(uint32_t handler_type, uint64_t image_base, uint64_t pc,
                                  uint64_t entry, uint64_t ctx, uint64_t& handler_data,
                                  uint64_t& establisher_frame) {
    handler_data = 0;
    establisher_frame = 0;

    uint64_t unwind_info = image_base + mem.read32(entry + 8);
    uint64_t function_start = image_base + mem.read32(entry);

    // A chained entry describes a fragment of another function; its parent's
    // codes apply after its own, so the walk simply continues into the parent.
    uint64_t handler = 0;
    uint64_t frame_base = ctx_rsp(*this, ctx);
    bool frame_base_set = false;
    // Set once the walk moves into a chained parent: a fragment exists only
    // because the whole prologue already ran, so every one of the parent's codes
    // applies regardless of code offsets.
    bool in_chained_parent = false;

    for (int chain = 0; chain < 32; ++chain) {
        uint8_t version_flags = mem.read8(unwind_info);
        uint8_t size_of_prolog = mem.read8(unwind_info + 1);
        uint8_t count_of_codes = mem.read8(unwind_info + 2);
        uint8_t frame_info = mem.read8(unwind_info + 3);
        uint32_t flags = static_cast<uint32_t>(version_flags >> 3);
        int frame_register = frame_info & 0xF;
        int frame_offset = (frame_info >> 4) & 0xF;
        uint64_t codes = unwind_info + 4;

        // Where the function's locals live: the frame register if it declared
        // one, otherwise the stack pointer as it stands.
        if (!frame_base_set) {
            if (frame_register)
                frame_base = ctx_reg(*this, ctx, frame_register) -
                             static_cast<uint64_t>(frame_offset) * 16;
            frame_base_set = true;
            establisher_frame = frame_base;
        }

        // How far into the prologue the interrupted instruction is: codes whose
        // offset is beyond that have not run yet and must not be undone.
        uint64_t prolog_offset = pc > function_start ? pc - function_start : 0;
        bool past_prolog = in_chained_parent || prolog_offset >= size_of_prolog;

        for (int i = 0; i < count_of_codes;) {
            uint64_t code = codes + static_cast<uint64_t>(i) * 2;
            uint8_t code_offset = mem.read8(code);
            uint8_t op = mem.read8(code + 1);
            int unwind_op = op & 0xF;
            int op_info = (op >> 4) & 0xF;
            bool applies = past_prolog || code_offset <= prolog_offset;
            int slots = 1;

            switch (unwind_op) {
                case 0:  // UWOP_PUSH_NONVOL
                    if (applies) {
                        uint64_t sp = ctx_rsp(*this, ctx);
                        set_ctx_reg(*this, ctx, unwind_reg(static_cast<uint8_t>(op_info)),
                                    mem.read64(sp));
                        set_ctx_rsp(*this, ctx, sp + 8);
                    }
                    break;
                case 1: {  // UWOP_ALLOC_LARGE
                    uint64_t size;
                    if (op_info == 0) {
                        size = static_cast<uint64_t>(mem.read16(code + 2)) * 8;
                        slots = 2;
                    } else {
                        size = mem.read32(code + 2);
                        slots = 3;
                    }
                    if (applies) set_ctx_rsp(*this, ctx, ctx_rsp(*this, ctx) + size);
                    break;
                }
                case 2:  // UWOP_ALLOC_SMALL
                    if (applies)
                        set_ctx_rsp(*this, ctx,
                                    ctx_rsp(*this, ctx) +
                                        (static_cast<uint64_t>(op_info) + 1) * 8);
                    break;
                case 3:  // UWOP_SET_FPREG
                    if (applies)
                        set_ctx_rsp(*this, ctx,
                                    ctx_reg(*this, ctx, frame_register) -
                                        static_cast<uint64_t>(frame_offset) * 16);
                    break;
                case 4: {  // UWOP_SAVE_NONVOL
                    uint64_t offset = static_cast<uint64_t>(mem.read16(code + 2)) * 8;
                    slots = 2;
                    if (applies)
                        set_ctx_reg(*this, ctx, unwind_reg(static_cast<uint8_t>(op_info)),
                                    mem.read64(frame_base + offset));
                    break;
                }
                case 5: {  // UWOP_SAVE_NONVOL_FAR
                    uint64_t offset = mem.read32(code + 2);
                    slots = 3;
                    if (applies)
                        set_ctx_reg(*this, ctx, unwind_reg(static_cast<uint8_t>(op_info)),
                                    mem.read64(frame_base + offset));
                    break;
                }
                case 6:  // UWOP_EPILOG: epilogue description, nothing to undo
                    slots = 2;
                    break;
                case 7:  // UWOP_SPARE
                    slots = 3;
                    break;
                case 8: {  // UWOP_SAVE_XMM128
                    uint64_t offset = static_cast<uint64_t>(mem.read16(code + 2)) * 16;
                    slots = 2;
                    if (applies) {
                        cpu_->xmm[op_info].q[0] = mem.read64(frame_base + offset);
                        cpu_->xmm[op_info].q[1] = mem.read64(frame_base + offset + 8);
                        mem.write64(ctx + kOffXmm + static_cast<uint64_t>(op_info) * 16,
                                    cpu_->xmm[op_info].q[0]);
                        mem.write64(ctx + kOffXmm + static_cast<uint64_t>(op_info) * 16 + 8,
                                    cpu_->xmm[op_info].q[1]);
                    }
                    break;
                }
                case 9: {  // UWOP_SAVE_XMM128_FAR
                    uint64_t offset = mem.read32(code + 2);
                    slots = 3;
                    if (applies) {
                        mem.write64(ctx + kOffXmm + static_cast<uint64_t>(op_info) * 16,
                                    mem.read64(frame_base + offset));
                        mem.write64(ctx + kOffXmm + static_cast<uint64_t>(op_info) * 16 + 8,
                                    mem.read64(frame_base + offset + 8));
                    }
                    break;
                }
                case 10: {  // UWOP_PUSH_MACHFRAME - only in kernel trap frames
                    if (applies) {
                        uint64_t sp = ctx_rsp(*this, ctx) + (op_info ? 8 : 0);
                        set_ctx_rip(*this, ctx, mem.read64(sp));
                        set_ctx_rsp(*this, ctx, mem.read64(sp + 24));
                    }
                    break;
                }
                default:
                    break;
            }
            i += slots;
        }

        if (flags & kUnwFlagChaininfo) {
            // The chained RUNTIME_FUNCTION follows the codes, padded to an even
            // number of slots.
            uint64_t chained = codes + ((static_cast<uint64_t>(count_of_codes) + 1) & ~1ull) * 2;
            unwind_info = image_base + mem.read32(chained + 8);
            function_start = image_base + mem.read32(chained);
            // The parent's codes all apply - and that must be said explicitly,
            // not by faking pc.  Setting pc to the parent's start (the old code)
            // made prolog_offset zero, which *disables* every code instead: the
            // fragment's frame never unwound and the walk read a garbage return
            // address.  c2.dll found this, because a profile-optimised binary is
            // full of split functions and small tests contain none.
            in_chained_parent = true;
            continue;
        }

        if ((flags & handler_type) && (flags & (kUnwFlagEhandler | kUnwFlagUhandler))) {
            uint64_t after = codes + ((static_cast<uint64_t>(count_of_codes) + 1) & ~1ull) * 2;
            handler = image_base + mem.read32(after);
            handler_data = after + 4;
        }
        break;
    }

    // Every non-leaf frame ends with the return address on top of the stack.
    uint64_t sp = ctx_rsp(*this, ctx);
    set_ctx_rip(*this, ctx, mem.read64(sp));
    set_ctx_rsp(*this, ctx, sp + 8);
    return handler;
}

// ---------------------------------------------------------------------------
// Dispatch and unwind
// ---------------------------------------------------------------------------

// One frame step for a context with no unwind information: a leaf function,
// whose return address is simply on top of the stack.
void Emulator::unwind_leaf(uint64_t ctx) {
    uint64_t sp = ctx_rsp(*this, ctx);
    set_ctx_rip(*this, ctx, mem.read64(sp));
    set_ctx_rsp(*this, ctx, sp + 8);
}

uint64_t Emulator::exception_scratch(uint64_t size) {
    // A per-emulator scratch block for the records and contexts handed to
    // handlers.  Throwing is not a hot path, but it can nest (a destructor may
    // throw), so each dispatch takes a fresh slice rather than sharing one.
    std::vector<uint8_t> zeros(static_cast<size_t>(size), 0);
    return alloc_guest_data(zeros.data(), zeros.size());
}

void Emulator::dispatch_exception(uint64_t record, uint64_t ctx) {
    uint64_t dispatcher = exception_scratch(kDispatcherSize);
    uint64_t code = mem.read32(record + kOffCode);

    for (int depth = 0; depth < 256; ++depth) {
        uint64_t pc = ctx_rip(*this, ctx);
        if (!pc) break;
        uint64_t image_base = 0, entry = 0;
        if (!lookup_function_entry(pc, image_base, entry)) {
            unwind_leaf(ctx);
            continue;
        }

        // The handler sees this frame's context; the walk continues with the
        // caller's, so unwind into a copy.
        uint64_t caller = exception_scratch(kContextSize);
        std::vector<uint8_t> bytes(static_cast<size_t>(kContextSize));
        mem.read(ctx, bytes.data(), bytes.size());
        mem.write(caller, bytes.data(), bytes.size());

        uint64_t handler_data = 0, establisher = 0;
        uint64_t handler = virtual_unwind(kUnwFlagEhandler, image_base, pc, entry, caller,
                                         handler_data, establisher);
        if (handler) {
            mem.write64(dispatcher + 0x00, pc);
            mem.write64(dispatcher + 0x08, image_base);
            mem.write64(dispatcher + 0x10, entry);
            mem.write64(dispatcher + 0x18, establisher);
            mem.write64(dispatcher + 0x20, 0);           // TargetIp
            mem.write64(dispatcher + 0x28, ctx);
            mem.write64(dispatcher + 0x30, handler);
            mem.write64(dispatcher + 0x38, handler_data);
            mem.write64(dispatcher + 0x40, 0);           // HistoryTable
            mem.write32(dispatcher + 0x48, 0);           // ScopeIndex
            log_call("dispatch: frame 0x%llX handler 0x%llX",
                     (unsigned long long)establisher, (unsigned long long)handler);
            uint64_t disposition = call_guest(handler, {record, establisher, ctx, dispatcher});
            // A handler may end the process outright - an unhandled-exception
            // filter does - and then there is nothing left to dispatch.
            if (cpu_->halted) return;
            if (disposition == kContinueExecution) {
                // The handler fixed whatever it was; resume where it says.
                throw UnwindTransfer{ctx};
            }
            if (disposition == kCollidedUnwind) {
                // A handler faulted while unwinding.  Nothing here can recover
                // meaningfully, and pretending otherwise would loop forever.
                throw CpuError(cpu_->rip, "collided unwind while dispatching an exception");
            }
        }
        std::vector<uint8_t> back(static_cast<size_t>(kContextSize));
        mem.read(caller, back.data(), back.size());
        mem.write(ctx, back.data(), back.size());
    }

    // Nobody claimed it.  Windows would run the unhandled-exception filter and
    // end the process; saying which code it was is the useful part.
    flush_guest_output();
    std::fprintf(stderr,
                 "x86emu: unhandled exception 0x%08llX in the guest (no handler accepted it)\n",
                 (unsigned long long)code);
    // Which instruction raised it is the first thing anyone needs, and for a C++
    // throw the second parameter points at the ThrowInfo that names the type.
    uint64_t where = mem.read64(record + kOffAddress);
    std::fprintf(stderr, "  raised at %s\n", describe_address(where).c_str());
    if (code == 0xE06D7363u) {
        uint32_t nparams = mem.read32(record + 0x18);
        for (uint32_t i = 0; i < nparams && i < 4; ++i)
            std::fprintf(stderr, "  param[%u] = 0x%llX\n", i,
                         (unsigned long long)mem.read64(record + kOffParams + 8 * i));
    }
    std::fprintf(stderr, "%s", stack_trace(12).c_str());
    exit_process(static_cast<int>(code));
}

void Emulator::unwind_to(uint64_t target_frame, uint64_t target_ip, uint64_t record,
                         uint64_t return_value, uint64_t ctx) {
    uint64_t dispatcher = exception_scratch(kDispatcherSize);
    uint32_t flags = mem.read32(record + kOffFlags) | kExceptionUnwinding;
    if (!target_frame) flags |= kExceptionExitUnwind;

    for (int depth = 0; depth < 256; ++depth) {
        uint64_t pc = ctx_rip(*this, ctx);
        if (!pc) break;
        uint64_t image_base = 0, entry = 0;
        if (!lookup_function_entry(pc, image_base, entry)) {
            unwind_leaf(ctx);
            continue;
        }

        uint64_t caller = exception_scratch(kContextSize);
        std::vector<uint8_t> bytes(static_cast<size_t>(kContextSize));
        mem.read(ctx, bytes.data(), bytes.size());
        mem.write(caller, bytes.data(), bytes.size());

        uint64_t handler_data = 0, establisher = 0;
        uint64_t handler = virtual_unwind(kUnwFlagUhandler, image_base, pc, entry, caller,
                                         handler_data, establisher);
        bool is_target = establisher == target_frame;
        if (handler) {
            uint32_t frame_flags = flags | (is_target ? kExceptionTargetUnwind : 0u);
            mem.write32(record + kOffFlags, frame_flags);
            mem.write64(dispatcher + 0x00, pc);
            mem.write64(dispatcher + 0x08, image_base);
            mem.write64(dispatcher + 0x10, entry);
            mem.write64(dispatcher + 0x18, establisher);
            mem.write64(dispatcher + 0x20, is_target ? target_ip : 0);
            mem.write64(dispatcher + 0x28, ctx);
            mem.write64(dispatcher + 0x30, handler);
            mem.write64(dispatcher + 0x38, handler_data);
            mem.write64(dispatcher + 0x40, 0);
            mem.write32(dispatcher + 0x48, 0);
            log_call("unwind: frame 0x%llX handler 0x%llX%s",
                     (unsigned long long)establisher, (unsigned long long)handler,
                     is_target ? " (target)" : "");
            uint64_t disposition = call_guest(handler, {record, establisher, ctx, dispatcher});
            if (cpu_->halted) return;
            if (disposition == kCollidedUnwind)
                throw CpuError(cpu_->rip, "collided unwind while unwinding");
        }
        if (is_target) break;
        std::vector<uint8_t> back(static_cast<size_t>(kContextSize));
        mem.read(caller, back.data(), back.size());
        mem.write(ctx, back.data(), back.size());
    }

    // An unwind that consolidates runs a callback now that the frames are gone,
    // and continues wherever that callback says - which for C++ means: call the
    // catch block, then carry on after it.  The callback deliberately runs
    // before the context is restored, on the stack below the target frame, so
    // nothing it does disturbs the frame it is about to return into.
    if (mem.read32(record + kOffCode) == kStatusUnwindConsolidate &&
        mem.read32(record + kOffNumParams) >= 1) {
        uint64_t callback = mem.read64(record + kOffParams);
        log_call("unwind consolidate: callback 0x%llX", (unsigned long long)callback);
        uint64_t continuation = call_guest(callback, {record});
        if (continuation) target_ip = continuation;
    }

    // Land in the handler: the target address, with the return value the
    // unwinder was given.
    set_ctx_rip(*this, ctx, target_ip);
    set_ctx_reg(*this, ctx, RAX, return_value);
    throw UnwindTransfer{ctx};
}

void Emulator::apply_unwind_transfer(const UnwindTransfer& t) {
    log_call("resuming at 0x%llX with rsp 0x%llX after unwinding",
             (unsigned long long)ctx_rip(*this, t.context),
             (unsigned long long)ctx_rsp(*this, t.context));
    restore_context(*this, t.context);
}

void Emulator::raise_guest_exception(uint32_t code, uint32_t flags,
                                     const std::vector<uint64_t>& params, uint64_t address) {
    uint64_t record = exception_scratch(kRecordSize);
    mem.write32(record + kOffCode, code);
    mem.write32(record + kOffFlags, flags);
    mem.write64(record + kOffNested, 0);
    mem.write64(record + kOffAddress, address);
    mem.write32(record + kOffNumParams, static_cast<uint32_t>(params.size()));
    for (size_t i = 0; i < params.size() && i < 15; ++i)
        mem.write64(record + kOffParams + i * 8, params[i]);

    uint64_t ctx = exception_scratch(kContextSize);
    capture_context(*this, ctx);
    // The throw point is where the caller will resume, not this hook: the call
    // that raised has already pushed its return address.
    uint64_t sp = cpu_->regs[RSP];
    set_ctx_rip(*this, ctx, mem.read64(sp));
    set_ctx_rsp(*this, ctx, sp + 8);
    if (!address) mem.write64(record + kOffAddress, ctx_rip(*this, ctx));

    dispatch_exception(record, ctx);
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

void Emulator::install_exception_hooks() {
    if (!is64()) {
        install_seh32_hooks();
        return;
    }
    auto win32 = [this](const char* name, std::function<void(Emulator&)> fn) {
        add_hook(name, 0, std::move(fn));
    };

    win32("RtlCaptureContext", [](Emulator& e) {
        uint64_t ctx = e.arg_slot(0);
        capture_context(e, ctx);
        // As the caller sees it: RIP is where this call returns, and RSP is what
        // it will be once the return address has been popped.
        uint64_t sp = e.cpu().regs[RSP];
        e.mem.write64(ctx + kOffRip, e.mem.read64(sp));
        e.mem.write64(ctx + kOffRegs + RSP * 8, sp + 8);
        e.set_result(0);
    });

    // (ControlPc, *ImageBase, HistoryTable) -> PRUNTIME_FUNCTION
    win32("RtlLookupFunctionEntry", [](Emulator& e) {
        uint64_t image_base = 0, entry = 0;
        bool found = e.lookup_function_entry(e.arg_slot(0), image_base, entry);
        if (e.arg_slot(1)) e.mem.write64(e.arg_slot(1), found ? image_base : 0);
        e.set_result(found ? entry : 0);
    });

    win32("RtlPcToFileHeader", [](Emulator& e) {
        Module* m = e.module_for(e.arg_slot(0));
        uint64_t base = m ? m->image.base : 0;
        if (e.arg_slot(1)) e.mem.write64(e.arg_slot(1), base);
        e.set_result(base);
    });

    // (HandlerType, ImageBase, ControlPc, FunctionEntry, ContextRecord,
    //  *HandlerData, *EstablisherFrame, ContextPointers)
    win32("RtlVirtualUnwind", [](Emulator& e) {
        Args a(e);
        uint32_t handler_type = static_cast<uint32_t>(a.next_int(4));
        uint64_t image_base = a.next_ptr();
        uint64_t pc = a.next_ptr();
        uint64_t entry = a.next_ptr();
        uint64_t ctx = a.next_ptr();
        uint64_t handler_data_out = a.next_ptr();
        uint64_t frame_out = a.next_ptr();
        uint64_t handler_data = 0, establisher = 0;
        uint64_t handler =
            e.virtual_unwind(handler_type, image_base, pc, entry, ctx, handler_data, establisher);
        if (handler_data_out) e.mem.write64(handler_data_out, handler_data);
        if (frame_out) e.mem.write64(frame_out, establisher);
        e.set_result(handler);
    });

    // (code, flags, nparams, params)
    win32("RaiseException", [](Emulator& e) {
        uint32_t code = static_cast<uint32_t>(e.arg_slot(0));
        uint32_t flags = static_cast<uint32_t>(e.arg_slot(1));
        uint64_t n = e.arg_slot(2);
        uint64_t params_ptr = e.arg_slot(3);
        std::vector<uint64_t> params;
        for (uint64_t i = 0; i < n && i < 15; ++i)
            params.push_back(params_ptr ? e.mem.read64(params_ptr + i * 8) : 0);
        e.log_call("RaiseException 0x%08X, %llu parameters", code, (unsigned long long)n);
        e.raise_guest_exception(code, flags, params, 0);
    });

    // (TargetFrame, TargetIp, ExceptionRecord, ReturnValue, ContextRecord, HistoryTable)
    win32("RtlUnwindEx", [](Emulator& e) {
        Args a(e);
        uint64_t target_frame = a.next_ptr();
        uint64_t target_ip = a.next_ptr();
        uint64_t record = a.next_ptr();
        uint64_t return_value = a.next_ptr();
        uint64_t ctx = a.next_ptr();
        if (!record) {
            record = e.exception_scratch(kRecordSize);
            e.mem.write32(record + kOffCode, kStatusUnwind);
            e.mem.write32(record + kOffFlags, kExceptionNoncontinuable);
        }
        if (!ctx) {
            ctx = e.exception_scratch(kContextSize);
            capture_context(e, ctx);
            uint64_t sp = e.cpu().regs[RSP];
            e.mem.write64(ctx + kOffRip, e.mem.read64(sp));
            e.mem.write64(ctx + kOffRegs + RSP * 8, sp + 8);
        }
        e.log_call("RtlUnwindEx to frame 0x%llX ip 0x%llX, record code 0x%08X",
                   (unsigned long long)target_frame, (unsigned long long)target_ip,
                   e.mem.read32(record + kOffCode));
        e.unwind_to(target_frame, target_ip, record, return_value, ctx);
    });

    // The legacy four-argument form; x64 code reaches it through the CRT.
    win32("RtlUnwind", [](Emulator& e) {
        uint64_t target_frame = e.arg_slot(0);
        uint64_t target_ip = e.arg_slot(1);
        uint64_t record = e.arg_slot(2);
        uint64_t return_value = e.arg_slot(3);
        if (!record) {
            record = e.exception_scratch(kRecordSize);
            e.mem.write32(record + kOffCode, kStatusUnwind);
            e.mem.write32(record + kOffFlags, kExceptionNoncontinuable);
        }
        uint64_t ctx = e.exception_scratch(kContextSize);
        capture_context(e, ctx);
        uint64_t sp = e.cpu().regs[RSP];
        e.mem.write64(ctx + kOffRip, e.mem.read64(sp));
        e.mem.write64(ctx + kOffRegs + RSP * 8, sp + 8);
        e.unwind_to(target_frame, target_ip, record, return_value, ctx);
    });

    // The language handler for C's __try/__except/__finally.  Its handler data
    // is a scope table: for each region containing the faulting address, either
    // a filter to evaluate (JumpTarget non-zero) or a __finally to run during
    // unwinding (JumpTarget zero).
    win32("__C_specific_handler", [](Emulator& e) {
        uint64_t record = e.arg_slot(0);
        uint64_t frame = e.arg_slot(1);
        uint64_t ctx = e.arg_slot(2);
        uint64_t dispatcher = e.arg_slot(3);
        uint64_t image_base = e.mem.read64(dispatcher + 0x08);
        uint64_t control_pc = e.mem.read64(dispatcher + 0x00);
        uint64_t table = e.mem.read64(dispatcher + 0x38);
        uint32_t flags = e.mem.read32(record + kOffFlags);
        bool unwinding = (flags & kExceptionUnwinding) != 0;
        uint32_t count = e.mem.read32(table);

        for (uint32_t i = 0; i < count; ++i) {
            uint64_t rec = table + 4 + static_cast<uint64_t>(i) * 16;
            uint64_t begin = image_base + e.mem.read32(rec);
            uint64_t end = image_base + e.mem.read32(rec + 4);
            uint32_t handler_rva = e.mem.read32(rec + 8);
            uint32_t jump_rva = e.mem.read32(rec + 12);
            if (control_pc < begin || control_pc >= end) continue;

            if (!jump_rva) {
                // A __finally: it runs while unwinding, never on the way in.
                if (unwinding && handler_rva)
                    e.call_guest(image_base + handler_rva, {1, frame});
                continue;
            }
            if (unwinding) continue;  // filters do not run on the unwind pass

            // Two EXCEPTION_POINTERS words the filter expects.
            uint64_t pointers = e.exception_scratch(16);
            e.mem.write64(pointers, record);
            e.mem.write64(pointers + 8, ctx);
            int64_t filter = 1;  // handler_rva == 1 means "always execute"
            if (handler_rva != 1)
                filter = static_cast<int64_t>(static_cast<int32_t>(
                    e.call_guest(image_base + handler_rva, {pointers, frame})));
            if (filter < 0) {          // EXCEPTION_CONTINUE_EXECUTION
                e.set_result(kContinueExecution);
                return;
            }
            if (filter > 0) {          // EXCEPTION_EXECUTE_HANDLER
                e.unwind_to(frame, image_base + jump_rva, record, 0, ctx);
                return;                // never reached: unwind_to transfers control
            }
        }
        e.set_result(kContinueSearch);
    });

    // A guest that traps deliberately (the CRT's fast-fail path) instead of
    // raising: report it rather than executing an undefined instruction.
    win32("__fastfail", [](Emulator& e) {
        e.flush_guest_output();
        std::fprintf(stderr, "x86emu: guest called __fastfail(%llu)\n",
                     (unsigned long long)e.arg_slot(0));
        e.exit_process(1);
    });
}

// ---------------------------------------------------------------------------
// 32-bit: the fs:[0] chain
// ---------------------------------------------------------------------------
//
// A 32-bit process keeps a linked list of {prev, handler} records on the stack,
// headed by TEB[0], and the kernel walks it.  That makes this the simpler half:
// there is no unwind table, no funclets and no consolidation - RtlUnwind pops
// records and returns, and the language runtime transfers control itself.

namespace {

constexpr uint64_t kContext32Size = 716;
constexpr uint64_t kOff32Edi = 0x9C;   // Edi, Esi, Ebx, Edx, Ecx, Eax, Ebp, Eip
constexpr uint64_t kOff32Eip = 0xB8;
constexpr uint64_t kOff32EFlags = 0xC0;
constexpr uint64_t kOff32Esp = 0xC4;
constexpr uint64_t kRecord32Size = 80;
constexpr uint64_t kOff32Code = 0x00;
constexpr uint64_t kOff32Flags = 0x04;
constexpr uint64_t kOff32Address = 0x0C;
constexpr uint64_t kOff32NumParams = 0x10;
constexpr uint64_t kOff32Params = 0x14;
constexpr uint32_t kEndOfChain = 0xFFFFFFFFu;

void capture_context32(Emulator& e, uint64_t ctx) {
    std::vector<uint8_t> zeros(static_cast<size_t>(kContext32Size), 0);
    e.mem.write(ctx, zeros.data(), zeros.size());
    e.mem.write32(ctx + 0, 0x10007);  // CONTEXT_FULL for i386
    static const int order[] = {RDI, RSI, RBX, RDX, RCX, RAX, RBP};
    for (int i = 0; i < 7; ++i)
        e.mem.write32(ctx + kOff32Edi + static_cast<uint64_t>(i) * 4,
                      static_cast<uint32_t>(e.cpu().regs[order[i]]));
    e.mem.write32(ctx + kOff32Eip, static_cast<uint32_t>(e.cpu().rip));
    e.mem.write32(ctx + kOff32EFlags, static_cast<uint32_t>(e.cpu().rflags));
    e.mem.write32(ctx + kOff32Esp, static_cast<uint32_t>(e.cpu().regs[RSP]));
}

}  // namespace

void Emulator::install_seh32_hooks() {
    auto win32 = [this](const char* name, int nargs, std::function<void(Emulator&)> fn) {
        add_hook(name, nargs * 4, std::move(fn));
    };

    // (code, flags, nparams, params)
    win32("RaiseException", 4, [](Emulator& e) {
        uint32_t code = static_cast<uint32_t>(e.arg_slot(0));
        uint32_t flags = static_cast<uint32_t>(e.arg_slot(1));
        uint64_t n = e.arg_slot(2), params_ptr = e.arg_slot(3);

        uint64_t record = e.exception_scratch(kRecord32Size);
        e.mem.write32(record + kOff32Code, code);
        e.mem.write32(record + kOff32Flags, flags);
        e.mem.write32(record + kOff32NumParams, static_cast<uint32_t>(n));
        for (uint64_t i = 0; i < n && i < 15; ++i)
            e.mem.write32(record + kOff32Params + i * 4,
                          params_ptr ? e.mem.read32(params_ptr + i * 4) : 0);

        uint64_t ctx = e.exception_scratch(kContext32Size);
        capture_context32(e, ctx);
        // The throw point is the caller, past the call that got here.
        uint64_t sp = e.cpu().regs[RSP];
        uint32_t ret = e.mem.read32(sp);
        e.mem.write32(ctx + kOff32Eip, ret);
        e.mem.write32(ctx + kOff32Esp, static_cast<uint32_t>(sp + 4 + 16));  // stdcall pops 4 args
        e.mem.write32(record + kOff32Address, ret);
        e.log_call("RaiseException 0x%08X (32-bit)", code);
        e.dispatch_exception32(record, ctx);
    });

    // (TargetFrame, TargetIp, ExceptionRecord, ReturnValue): pops the chain,
    // running each handler as an unwind, and *returns* - on x86 the language
    // runtime transfers control itself once this comes back.
    win32("RtlUnwind", 4, [](Emulator& e) {
        uint64_t target = e.arg_slot(0);
        uint64_t record = e.arg_slot(2);
        if (!record) {
            record = e.exception_scratch(kRecord32Size);
            e.mem.write32(record + kOff32Code, kStatusUnwind);
            e.mem.write32(record + kOff32Flags, kExceptionNoncontinuable);
        }
        e.unwind_chain32(target, record);
        e.set_result(0);
    });
    add_hook("RtlUnwindEx", 0, [](Emulator& e) {
        // The extended form takes the same first arguments in 32-bit code.
        uint64_t target = e.arg_slot(0);
        uint64_t record = e.arg_slot(2);
        if (record) e.unwind_chain32(target, record);
        e.set_result(0);
    });
}

void Emulator::dispatch_exception32(uint64_t record, uint64_t ctx) {
    // DISPATCHER_CONTEXT on x86 is a single word the handler may use to report a
    // nested registration; nothing here reads it back.
    uint64_t dispatcher = exception_scratch(4);
    uint64_t reg = mem.read32(cpu_->fs_base);

    for (int depth = 0; depth < 256 && reg && reg != kEndOfChain; ++depth) {
        uint64_t handler = mem.read32(reg + 4);
        log_call("dispatch (32-bit): registration 0x%llX handler 0x%llX",
                 (unsigned long long)reg, (unsigned long long)handler);
        uint64_t disposition = call_guest(handler, {record, reg, ctx, dispatcher});
        // A handler that accepts does not return: it runs the catch block and
        // jumps back into its own function, so the guest carries on inside the
        // nested interpreter loop until the program itself ends.  Reaching here
        // with the guest halted means exactly that - not a disposition.
        if (cpu_->halted) return;
        if (disposition == kContinueExecution) {
            // The handler dealt with it; resume from the context it may have
            // adjusted.
            cpu_->regs[RAX] = mem.read32(ctx + kOff32Edi + 5 * 4);
            static const int order[] = {RDI, RSI, RBX, RDX, RCX, RAX, RBP};
            for (int i = 0; i < 7; ++i)
                cpu_->regs[order[i]] = mem.read32(ctx + kOff32Edi + static_cast<uint64_t>(i) * 4);
            cpu_->regs[RSP] = mem.read32(ctx + kOff32Esp);
            cpu_->rip = mem.read32(ctx + kOff32Eip);
            retry_current_call();  // do not let the hook's epilogue touch the stack
            return;
        }
        // ExceptionNestedException (2) and ExceptionCollidedUnwind (3) say that
        // the handler hit trouble of its own; the dispatcher's answer to both is
        // to keep looking outward, which is also what a plain "continue search"
        // asks for.
        if (disposition > kCollidedUnwind)
            throw CpuError(cpu_->rip,
                           "a 32-bit exception handler returned disposition " +
                               std::to_string(disposition));
        reg = mem.read32(reg);
    }

    flush_guest_output();
    std::fprintf(stderr,
                 "x86emu: unhandled exception 0x%08X in the guest (no handler accepted it)\n",
                 mem.read32(record + kOff32Code));
    exit_process(static_cast<int>(mem.read32(record + kOff32Code)));
}

void Emulator::unwind_chain32(uint64_t target_frame, uint64_t record) {
    uint64_t dispatcher = exception_scratch(4);
    uint64_t ctx = exception_scratch(kContext32Size);
    capture_context32(*this, ctx);
    uint32_t flags = mem.read32(record + kOff32Flags) | kExceptionUnwinding;
    if (!target_frame || target_frame == kEndOfChain) flags |= kExceptionExitUnwind;
    mem.write32(record + kOff32Flags, flags);

    uint64_t reg = mem.read32(cpu_->fs_base);
    for (int depth = 0; depth < 256 && reg && reg != kEndOfChain && reg != target_frame; ++depth) {
        uint64_t handler = mem.read32(reg + 4);
        uint64_t next = mem.read32(reg);
        log_call("unwind (32-bit): registration 0x%llX handler 0x%llX",
                 (unsigned long long)reg, (unsigned long long)handler);
        call_guest(handler, {record, reg, ctx, dispatcher});
        // Pop as we go, so a handler that throws sees a consistent chain.
        mem.write32(cpu_->fs_base, static_cast<uint32_t>(next));
        reg = next;
    }
    if (target_frame && target_frame != kEndOfChain)
        mem.write32(cpu_->fs_base, static_cast<uint32_t>(target_frame));
}

}  // namespace x86emu
