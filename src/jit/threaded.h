// What the threaded handlers have in common, whichever guest they serve: the way a
// handler reads its operands (slots in the register file), hands over to the next
// op, and checks whether a store invalidated translated code.
#pragma once

#include <cstdint>

#include "engine.h"

namespace jit {

using Fn = const Uop* (*)(Ctx*, const Uop*);

#define S(o) (*reinterpret_cast<uint64_t*>(c->env + (o)))

// After a store that asked for it: leave the block if the store invalidated
// translated code, at the next instruction (imm2).
#define CHK_FLUSH()                                                  \
    do {                                                             \
        if ((u->flags & kFlagChk) && c->eng->epoch != c->epoch0) {   \
            c->partial = u->ni;                                      \
            Glue::set_pc(*c->cpu, static_cast<uint64_t>(u->imm2));   \
            return nullptr;                                          \
        }                                                            \
    } while (0)

// How a handler hands over to the next op.  With tail calls each handler ends in
// its own indirect jump, which a branch predictor can learn per handler; a loop
// that calls every handler from one place gives it a single jump to guess for
// the whole program.  Where the compiler cannot promise the tail call, the
// handler returns the next op and run() loops.
#if defined(JIT_NO_MUSTTAIL) || !(defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 15))
#define NEXT() return u + 1
#else
#define NEXT() [[gnu::musttail]] return (u + 1)->fn(c, u + 1)
#endif

template <int SZ> constexpr uint64_t mask_of() {
    return SZ == 8 ? ~0ull : ((1ull << (SZ * 8)) - 1);
}
template <int SZ> constexpr uint64_t sign_of() { return 1ull << (SZ * 8 - 1); }

// A guest's own ops.  Returns the handler for `o`, or nullptr if `o` is not one
// of the guest's (the backend then reports the op as unknown).
Fn guest_select(const Op& o);

}  // namespace jit
