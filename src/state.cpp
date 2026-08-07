// Saving a running guest, and putting it back.
//
// What makes this possible is that the guest's state is entirely guest-shaped.
// Its memory holds guest addresses, its registers hold guest addresses, and the
// emulator's own bookkeeping - where the heap has reached, which descriptors are
// open - is in the same terms.  None of it is a host pointer, so none of it
// cares how wide a host pointer is.  A state written by the native build loads
// into the WebAssembly build, where a pointer is four bytes instead of eight.
//
// The one thing that would break that is a host address written *into* guest
// memory, which is exactly what an accelerator shim does if it hands the guest
// its own malloc'd blocks.  Memory::map_contiguous exists so it does not have
// to.
//
// The format is a tagged stream: sections can be skipped by a reader that does
// not know them, and a version mismatch is refused outright rather than
// half-read.  Everything is little-endian, which is what both hosts are.

#include "emulator.h"
#include "files.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace x86emu {
namespace {

constexpr char kMagic[8] = {'X', '8', '6', 'E', 'M', 'U', 'S', 'T'};
constexpr uint32_t kVersion = 1;

// A section tag as one 32-bit word, so comparing tags is comparing integers.
constexpr uint32_t tag(const char (&s)[5]) {
    return (uint32_t)(uint8_t)s[0] | (uint32_t)(uint8_t)s[1] << 8 |
           (uint32_t)(uint8_t)s[2] << 16 | (uint32_t)(uint8_t)s[3] << 24;
}

// ---------------------------------------------------------------------------
// Writing.  Sections are built in memory and then framed, because a section's
// length is only known once it is finished and seeking back to patch it does
// not work on every stream a front end might hand us.

class Writer {
public:
    void u8(uint8_t v) { buf_.push_back(v); }
    void u16(uint16_t v) { raw(&v, sizeof v); }
    void u32(uint32_t v) { raw(&v, sizeof v); }
    void u64(uint64_t v) { raw(&v, sizeof v); }
    void i32(int32_t v) { raw(&v, sizeof v); }
    void f64(double v) { raw(&v, sizeof v); }
    void boolean(bool v) { u8(v ? 1 : 0); }
    void str(const std::string& s) {
        u64(s.size());
        raw(s.data(), s.size());
    }
    void raw(const void* p, size_t n) {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        buf_.insert(buf_.end(), b, b + n);
    }
    const std::vector<uint8_t>& bytes() const { return buf_; }
    void clear() { buf_.clear(); }

private:
    std::vector<uint8_t> buf_;
};

// ---------------------------------------------------------------------------
// Reading.  A truncated file is a real possibility - a snapshot taken of a
// long run is large and writing one can be interrupted - so every read is
// bounds-checked and the first failure poisons the reader.  A caller checks
// ok() once at the end rather than after every field.

class Reader {
public:
    Reader(const uint8_t* p, size_t n) : p_(p), n_(n) {}

    uint8_t u8() { return get<uint8_t>(); }
    uint16_t u16() { return get<uint16_t>(); }
    uint32_t u32() { return get<uint32_t>(); }
    uint64_t u64() { return get<uint64_t>(); }
    int32_t i32() { return get<int32_t>(); }
    double f64() { return get<double>(); }
    bool boolean() { return u8() != 0; }
    std::string str() {
        uint64_t n = u64();
        if (!ok_ || n > n_ - at_) return poison(), std::string();
        std::string s(reinterpret_cast<const char*>(p_ + at_), n);
        at_ += n;
        return s;
    }
    // Points into the buffer rather than copying: a page is 4 KiB and there can
    // be a hundred thousand of them.
    const uint8_t* block(uint64_t n) {
        if (!ok_ || n > n_ - at_) return poison(), nullptr;
        const uint8_t* r = p_ + at_;
        at_ += n;
        return r;
    }
    bool ok() const { return ok_; }
    uint64_t left() const { return ok_ ? n_ - at_ : 0; }

private:
    template <typename T> T get() {
        T v{};
        if (!ok_ || sizeof(T) > n_ - at_) return poison(), v;
        std::memcpy(&v, p_ + at_, sizeof v);
        at_ += sizeof v;
        return v;
    }
    void poison() { ok_ = false; }

    const uint8_t* p_;
    size_t n_;
    size_t at_ = 0;
    bool ok_ = true;
};

bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (n < 0) { std::fclose(f); return false; }
    out.resize((size_t)n);
    size_t got = n ? std::fread(out.data(), 1, (size_t)n, f) : 0;
    std::fclose(f);
    out.resize(got);
    return true;
}

// One page of a file mapping, for deciding whether the guest's copy still
// matches it.  Opening the file once per page would be the obvious way and the
// wrong one: a 460 MB library is 112,000 pages.
class FileCache {
public:
    // Returns false when the file cannot be read at all, which makes every page
    // of that mapping "different" and so carried in the snapshot.  That is the
    // safe direction to fail in.
    bool page(const std::string& path, uint64_t offset, const uint8_t*& out) {
        if (path != path_) {
            if (fp_) std::fclose(fp_);
            // The region records the path the *guest* asked for.  Opening that
            // literally finds nothing when the guest has a sysroot, which is
            // how a first attempt carried every page of a 460 MB library it
            // could have left on disk.
            fp_ = std::fopen(FileTable::host_path(path).c_str(), "rb");
            path_ = path;
        }
        if (!fp_) return false;
        if (std::fseek(fp_, (long)offset, SEEK_SET) != 0) return false;
        std::memset(buf_, 0, sizeof buf_);
        // A short read is not a failure: the last page of a mapping runs past
        // the end of the file and the rest of it reads as zero, which is what
        // the mapping itself does.
        size_t got = std::fread(buf_, 1, sizeof buf_, fp_);
        (void)got;
        out = buf_;
        return true;
    }
    ~FileCache() { if (fp_) std::fclose(fp_); }

private:
    std::FILE* fp_ = nullptr;
    std::string path_;
    uint8_t buf_[Memory::kPageSize];
};

}  // namespace

// ---------------------------------------------------------------------------

bool Emulator::save_state(const std::string& path) const {
    for (const auto& [fd, e] : files.entries()) {
        if (e.pipe_end) {
            std::fprintf(stderr, "save_state: descriptor %d is a pipe\n", fd);
            return false;
        }
    }

    std::FILE* out = std::fopen(path.c_str(), "wb");
    if (!out) {
        std::fprintf(stderr, "save_state: cannot write %s\n", path.c_str());
        return false;
    }
    std::fwrite(kMagic, 1, sizeof kMagic, out);
    uint32_t v = kVersion, reserved = 0;
    std::fwrite(&v, 1, sizeof v, out);
    std::fwrite(&reserved, 1, sizeof reserved, out);

    Writer w;
    auto section = [&](uint32_t t) {
        uint64_t n = w.bytes().size();
        std::fwrite(&t, 1, sizeof t, out);
        std::fwrite(&n, 1, sizeof n, out);
        std::fwrite(w.bytes().data(), 1, w.bytes().size(), out);
        w.clear();
    };

    // ---- the processor
    const Cpu& c = *cpu_;
    for (uint64_t r : c.regs) w.u64(r);
    for (const auto& x : c.xmm) { w.u64(x.q[0]); w.u64(x.q[1]); }
    w.u32(c.mxcsr);
    for (double s : c.st) w.f64(s);
    for (bool u : c.st_used) w.boolean(u);
    w.i32(c.st_top);
    w.u16(c.fpu_control);
    w.u16(c.fpu_status);
    w.u64(c.rip);
    w.u64(c.rflags);
    w.u64(c.fs_base);
    w.u64(c.gs_base);
    w.u16(c.fs_selector);
    w.u16(c.gs_selector);
    w.u64(c.instructions_executed);
    w.boolean(c.halted);
    w.i32(c.exit_code);
    section(tag("CPU "));

    // ---- where the allocators have got to
    w.u64(stack_base_); w.u64(stack_size_); w.u64(stack_top_);
    w.u64(heap_base_); w.u64(heap_next_); w.u64(heap_limit_);
    w.u64(mmap_next_); w.u64(mmap_limit_);
    w.boolean(mmap_no_reuse_);
    w.u64(mmap_free_.size());
    for (const auto& [base, size] : mmap_free_) { w.u64(base); w.u64(size); }
    w.u64(mmap_live_.size());
    for (const auto& [base, size] : mmap_live_) { w.u64(base); w.u64(size); }
    w.u64(misc_base_); w.u64(misc_next_);
    w.u64(brk_);
    w.u64(teb_base_);
    w.u64(errno_address_);
    w.u64(lconv_address_);
    w.u64(tls_array_);
    w.u32(next_tls_slot_);
    w.u64(last_error_);
    section(tag("ALLO"));

    // ---- the threads
    //
    // A thread's saved context is only written back when it is switched away
    // from, so the *running* thread's record is stale by however long its slice
    // has lasted - the live values are in the processor.  Writing the stale one
    // down would resume correctly and then, the first time the scheduler came
    // back around, jump to wherever that thread was a slice ago.
    w.u64(threads_.size());
    w.u64(current_thread_);
    w.u32(next_thread_id_);
    for (size_t i = 0; i < threads_.size(); i++) {
        const GuestThread& t0 = *threads_[i];
        const bool running = i == current_thread_;
        w.u32(t0.id);
        w.u64(t0.handle);
        for (int r = 0; r < 16; r++) w.u64(running ? c.regs[r] : t0.regs[r]);
        for (int x = 0; x < 16; x++) {
            const Cpu::Xmm& v = running ? c.xmm[x] : t0.xmm[x];
            w.u64(v.q[0]); w.u64(v.q[1]);
        }
        for (int s = 0; s < 8; s++) w.f64(running ? c.st[s] : t0.st[s]);
        for (int s = 0; s < 8; s++) w.boolean(running ? c.st_used[s] : t0.st_used[s]);
        w.i32(running ? c.st_top : t0.st_top);
        w.u16(running ? c.fpu_control : t0.fpu_control);
        w.u16(running ? c.fpu_status : t0.fpu_status);
        w.u32(running ? c.mxcsr : t0.mxcsr);
        w.u64(running ? c.rip : t0.rip);
        w.u64(running ? c.rflags : t0.rflags);
        w.u64(running ? c.fs_base : t0.fs_base);
        w.u64(running ? c.gs_base : t0.gs_base);
        const GuestThread* t = &t0;
        w.u64(t->stack_base); w.u64(t->stack_size);
        w.u64(t->teb);
        w.u64(t->tls_array);
        w.u64(t->tls_slots.size());
        for (uint64_t s : t->tls_slots) w.u64(s);

        // A thread waiting on a host-side predicate is written down as
        // runnable.  The predicate is a closure and cannot cross, but it does
        // not have to: a thread blocks by stepping its instruction pointer back
        // onto the syscall, or by arranging for the same hook to be called
        // again, so resuming it simply performs the operation a second time and
        // blocks again on a predicate built there and then.  That the operation
        // is idempotent up to the blocking point is what block_syscall_retry
        // and block_hook_retry already require of their callers.
        GuestThread::State state = t->state;
        uint64_t wait_handle = t->wait_handle;
        if (t->wait_predicate) {
            state = GuestThread::State::Runnable;
            wait_handle = 0;
        }
        w.u8((uint8_t)state);
        w.u32(t->exit_code);
        w.u64(wait_handle);
        w.u64(t->wake_at);
        w.u64(t->clear_child_tid);
    }
    section(tag("THRD"));

    // ---- the waitable objects a thread's wait_handle refers to
    w.u64(sync_objects_.size());
    for (const auto& [handle, o] : sync_objects_) {
        w.u64(handle);
        w.u8((uint8_t)o.kind);
        w.boolean(o.manual_reset);
        w.boolean(o.signalled);
        w.u64((uint64_t)o.count);
        w.u32(o.owner);
        w.u64((uint64_t)o.recursion);
    }
    w.u64(next_sync_handle_);
    w.u64(named_objects_.size());
    for (const auto& [name, handle] : named_objects_) {
        w.str(name);
        w.u64(handle);
    }
    section(tag("SYNC"));

    // ---- the open descriptors, as paths and offsets
    //
    // A descriptor is a host stream, which cannot cross to another host.  What
    // can is where it points: the path, how it was opened, and how far in it
    // is.  Reopening and seeking there reproduces everything a guest can
    // observe about it.
    {
        const auto& entries = files.entries();
        w.u64(entries.size());
        for (const auto& [fd, e] : entries) {
            w.i32(fd);
            w.str(e.path);
            w.boolean(e.readable);
            w.boolean(e.writable);
            w.boolean(e.append);
            w.boolean(e.standard_stream);
            w.boolean(e.is_tty);
            w.boolean(e.is_directory);
            w.boolean(e.text_mode);
            w.u8((uint8_t)e.wide_io);
            w.boolean(e.cloexec);
            w.boolean(e.closed);
            long at = e.fp ? std::ftell(e.fp.get()) : 0;
            w.u64(at < 0 ? 0 : (uint64_t)at);
        }
    }
    section(tag("FDS "));

    // ---- the memory map, then the memory
    const auto& regions = mem.regions();
    w.u64(regions.size());
    for (const auto& r : regions) {
        w.u64(r.base);
        w.u64(r.size);
        w.str(r.name);
        w.str(r.file);
        w.u64(r.file_offset);
        w.boolean(r.contiguous);
    }
    section(tag("REGN"));

    // Which pages exist at all.  Not the same question as which pages have
    // something in them: a heap that has grown by a megabyte has a megabyte of
    // pages that are mapped, empty, and inside no named region, and a guest
    // that faults on the first write into its own heap is what leaving them out
    // produces.
    {
        std::vector<uint64_t> mapped = mem.mapped_pages();
        w.u64(mapped.size());
        for (uint64_t index : mapped) w.u64(index);
    }
    section(tag("MAPD"));

    // A page that still holds what the file put there is not written: the file
    // is still on disk and reading it back is free.  For a guest that has
    // mapped a 460 MB runtime and a 98 MB dictionary this is most of the
    // snapshot.
    {
        FileCache cache;
        std::vector<uint64_t> live = mem.live_pages();
        std::vector<uint64_t> keep, from_file;
        keep.reserve(live.size());
        // Where the carried pages are, by mapping.  Whether a state is worth
        // shrinking, and which end to start at, is a question about this table
        // and not one worth guessing at.
        std::map<std::string, uint64_t> by_region;
        uint64_t blank = 0;
        for (uint64_t index : live) {
            // A page of zeros is not worth carrying: it is already reserved by
            // the section above, and a reserved page reads as zero.
            const uint8_t* data = mem.page_data(index);
            if (data) {
                bool all_zero = true;
                for (uint64_t i = 0; i < Memory::kPageSize; i++)
                    if (data[i]) { all_zero = false; break; }
                if (all_zero) { blank++; continue; }
            }
            uint64_t addr = index * Memory::kPageSize;
            const Memory::Region* home = nullptr;
            for (const auto& r : regions)
                if (addr >= r.base && addr < r.base + r.size && !r.file.empty()) {
                    home = &r;
                    break;
                }
            if (home) {
                uint64_t off = home->file_offset + (addr - home->base);
                const uint8_t* original = nullptr;
                if (cache.page(home->file, off, original) &&
                    std::memcmp(original, mem.page_data(index), Memory::kPageSize) == 0) {
                    from_file.push_back(index);
                    continue;
                }
            }
            keep.push_back(index);
            const Memory::Region* named = home;
            if (!named)
                for (const auto& r : regions)
                    if (addr >= r.base && addr < r.base + r.size) named = &r;
            by_region[named ? named->name : std::string("(anonymous)")]++;
        }
        w.u64(keep.size());
        for (uint64_t index : keep) {
            w.u64(index);
            w.raw(mem.page_data(index), Memory::kPageSize);
        }
        // The ones left to the files are named, not carried.  Naming them
        // matters as much as leaving them out: a region is reserved lazily, and
        // reading the whole of a 460 MB mapping back would turn a hundred
        // thousand pages that were never touched into a hundred thousand pages
        // that are.
        w.u64(from_file.size());
        for (uint64_t index : from_file) w.u64(index);
        std::fprintf(stderr,
                     "save_state: %llu pages carried, %llu left to the files, "
                     "%llu blank\n",
                     (unsigned long long)keep.size(),
                     (unsigned long long)from_file.size(),
                     (unsigned long long)blank);
        std::vector<std::pair<uint64_t, std::string>> ranked;
        for (const auto& [name, n] : by_region) ranked.emplace_back(n, name);
        std::sort(ranked.rbegin(), ranked.rend());
        for (size_t i = 0; i < ranked.size() && i < 12; i++)
            std::fprintf(stderr, "save_state:   %8.1f MB  %s\n",
                         ranked[i].first * Memory::kPageSize / 1048576.0,
                         ranked[i].second.c_str());
    }
    section(tag("PAGE"));

    uint32_t end = tag("END ");
    uint64_t zero = 0;
    std::fwrite(&end, 1, sizeof end, out);
    std::fwrite(&zero, 1, sizeof zero, out);
    bool good = std::ferror(out) == 0;
    std::fclose(out);
    if (!good) std::fprintf(stderr, "save_state: write failed\n");
    return good;
}

// ---------------------------------------------------------------------------

bool Emulator::load_state(const std::string& path) {
    std::vector<uint8_t> file;
    if (!read_file(path, file)) {
        std::fprintf(stderr, "load_state: cannot read %s\n", path.c_str());
        return false;
    }
    Reader r(file.data(), file.size());
    const uint8_t* magic = r.block(sizeof kMagic);
    if (!magic || std::memcmp(magic, kMagic, sizeof kMagic) != 0) {
        std::fprintf(stderr, "load_state: %s is not a saved state\n", path.c_str());
        return false;
    }
    uint32_t version = r.u32();
    r.u32();  // reserved
    if (version != kVersion) {
        std::fprintf(stderr, "load_state: version %u, this build writes %u\n",
                     version, kVersion);
        return false;
    }

    std::vector<Memory::Region> regions;
    while (r.ok() && r.left() >= 12) {
        uint32_t t = r.u32();
        uint64_t n = r.u64();
        if (t == tag("END ")) break;
        const uint8_t* body = r.block(n);
        if (!body) break;
        Reader s(body, (size_t)n);

        if (t == tag("CPU ")) {
            Cpu& c = *cpu_;
            for (uint64_t& reg : c.regs) reg = s.u64();
            for (auto& x : c.xmm) { x.q[0] = s.u64(); x.q[1] = s.u64(); }
            c.mxcsr = s.u32();
            for (double& v : c.st) v = s.f64();
            for (bool& u : c.st_used) u = s.boolean();
            c.st_top = s.i32();
            c.fpu_control = s.u16();
            c.fpu_status = s.u16();
            c.rip = s.u64();
            c.rflags = s.u64();
            c.fs_base = s.u64();
            c.gs_base = s.u64();
            c.fs_selector = s.u16();
            c.gs_selector = s.u16();
            c.instructions_executed = s.u64();
            c.halted = s.boolean();
            c.exit_code = s.i32();
        } else if (t == tag("ALLO")) {
            stack_base_ = s.u64(); stack_size_ = s.u64(); stack_top_ = s.u64();
            heap_base_ = s.u64(); heap_next_ = s.u64(); heap_limit_ = s.u64();
            mmap_next_ = s.u64(); mmap_limit_ = s.u64();
            mmap_no_reuse_ = s.boolean();
            mmap_free_.clear();
            for (uint64_t i = 0, k = s.u64(); i < k && s.ok(); i++) {
                uint64_t base = s.u64(), size = s.u64();
                mmap_free_.emplace_back(base, size);
            }
            mmap_live_.clear();
            for (uint64_t i = 0, k = s.u64(); i < k && s.ok(); i++) {
                uint64_t base = s.u64(), size = s.u64();
                mmap_live_[base] = size;
            }
            misc_base_ = s.u64(); misc_next_ = s.u64();
            brk_ = s.u64();
            teb_base_ = s.u64();
            errno_address_ = s.u64();
            lconv_address_ = s.u64();
            tls_array_ = s.u64();
            next_tls_slot_ = s.u32();
            last_error_ = s.u64();
        } else if (t == tag("THRD")) {
            uint64_t count = s.u64();
            current_thread_ = (size_t)s.u64();
            next_thread_id_ = s.u32();
            threads_.clear();
            for (uint64_t i = 0; i < count && s.ok(); i++) {
                auto th = std::make_unique<GuestThread>();
                th->id = s.u32();
                th->handle = s.u64();
                for (uint64_t& reg : th->regs) reg = s.u64();
                for (auto& x : th->xmm) { x.q[0] = s.u64(); x.q[1] = s.u64(); }
                for (double& v : th->st) v = s.f64();
                for (bool& u : th->st_used) u = s.boolean();
                th->st_top = s.i32();
                th->fpu_control = s.u16();
                th->fpu_status = s.u16();
                th->mxcsr = s.u32();
                th->rip = s.u64();
                th->rflags = s.u64();
                th->fs_base = s.u64();
                th->gs_base = s.u64();
                th->stack_base = s.u64(); th->stack_size = s.u64();
                th->teb = s.u64();
                th->tls_array = s.u64();
                th->tls_slots.clear();
                for (uint64_t j = 0, k = s.u64(); j < k && s.ok(); j++)
                    th->tls_slots.push_back(s.u64());
                th->state = (GuestThread::State)s.u8();
                th->exit_code = s.u32();
                th->wait_handle = s.u64();
                th->wake_at = s.u64();
                th->clear_child_tid = s.u64();
                threads_.push_back(std::move(th));
            }
            if (current_thread_ >= threads_.size()) current_thread_ = 0;
        } else if (t == tag("SYNC")) {
            sync_objects_.clear();
            for (uint64_t i = 0, k = s.u64(); i < k && s.ok(); i++) {
                uint64_t handle = s.u64();
                SyncObject o;
                o.kind = (SyncObject::Kind)s.u8();
                o.manual_reset = s.boolean();
                o.signalled = s.boolean();
                o.count = (int64_t)s.u64();
                o.owner = s.u32();
                o.recursion = (int64_t)s.u64();
                sync_objects_[handle] = o;
            }
            next_sync_handle_ = s.u64();
            named_objects_.clear();
            for (uint64_t i = 0, k = s.u64(); i < k && s.ok(); i++) {
                std::string name = s.str();
                named_objects_[name] = s.u64();
            }
        } else if (t == tag("FDS ")) {
            uint64_t count = s.u64();
            for (uint64_t i = 0; i < count && s.ok(); i++) {
                int fd = s.i32();
                std::string fpath = s.str();
                FileTable::OpenFlags flags;
                flags.read = s.boolean();
                flags.write = s.boolean();
                flags.append = s.boolean();
                bool standard = s.boolean();
                s.boolean();  // is_tty, decided again by the host it lands on
                bool directory = s.boolean();
                bool text = s.boolean();
                flags.wide_io = (FileTable::WideIo)s.u8();
                s.boolean();  // cloexec: only execve reads it, and that is over
                bool closed = s.boolean();
                uint64_t at = s.u64();
                flags.binary = !text;
                if (closed || directory || standard) continue;
                if (!files.restore(fd, fpath, flags, at))
                    std::fprintf(stderr, "load_state: %s is gone (fd %d)\n",
                                 fpath.c_str(), fd);
            }
        } else if (t == tag("REGN")) {
            for (uint64_t i = 0, k = s.u64(); i < k && s.ok(); i++) {
                Memory::Region region;
                region.base = s.u64();
                region.size = s.u64();
                region.name = s.str();
                region.file = s.str();
                region.file_offset = s.u64();
                region.contiguous = s.boolean();
                regions.push_back(region);
            }
            // The address space is rebuilt from what was saved, not merged with
            // whatever load() happened to lay down: a restored guest must see
            // its own map and nothing else.
            mem.reset();
            for (const auto& region : regions) {
                if (region.contiguous)
                    mem.map_contiguous(region.base, region.size, region.name);
                else
                    mem.map(region.base, region.size, region.name);
                mem.set_region_file(region.base, region.file, region.file_offset);
            }
        } else if (t == tag("MAPD")) {
            for (uint64_t i = 0, k = s.u64(); i < k && s.ok(); i++) {
                uint64_t addr = s.u64() * Memory::kPageSize;
                if (!mem.is_mapped(addr)) mem.map(addr, Memory::kPageSize);
            }
        } else if (t == tag("PAGE")) {
            // The pages that differed, then the ones that did not, read back
            // from the files they came from.
            uint64_t count = s.u64();
            for (uint64_t i = 0; i < count && s.ok(); i++) {
                uint64_t index = s.u64();
                const uint8_t* data = s.block(Memory::kPageSize);
                if (!data) break;
                uint64_t addr = index * Memory::kPageSize;
                // A page can be live without belonging to a named region, so
                // the map rebuilt above does not necessarily cover it.  map()
                // leaves what is already there alone.
                if (!mem.is_mapped(addr)) mem.map(addr, Memory::kPageSize);
                mem.write(addr, data, Memory::kPageSize);
            }
            FileCache cache;
            uint64_t restored = s.u64(), missing = 0;
            // Which file, not how many.  A page that was left to a file and
            // cannot be read back is a hole in the guest's code, and it shows
            // up as an invalid instruction a long way from here - so the file's
            // name is the whole of the diagnosis.
            std::map<std::string, uint64_t> lost;
            for (uint64_t i = 0; i < restored && s.ok(); i++) {
                uint64_t index = s.u64();
                uint64_t addr = index * Memory::kPageSize;
                const Memory::Region* home = nullptr;
                for (const auto& region : regions)
                    if (addr >= region.base && addr < region.base + region.size &&
                        !region.file.empty()) {
                        home = &region;
                        break;
                    }
                const uint8_t* page = nullptr;
                if (!home ||
                    !cache.page(home->file, home->file_offset + (addr - home->base), page)) {
                    missing++;
                    lost[home ? home->file : std::string("(no mapping)")]++;
                    continue;
                }
                if (!mem.is_mapped(addr)) mem.map(addr, Memory::kPageSize);
                mem.write(addr, page, Memory::kPageSize);
            }
            std::fprintf(stderr, "load_state: %llu pages carried, %llu from the files\n",
                         (unsigned long long)count,
                         (unsigned long long)(restored - missing));
            for (const auto& [file, n] : lost)
                std::fprintf(stderr,
                             "load_state:   %llu pages missing from %s - the guest "
                             "will run into the hole\n",
                             (unsigned long long)n, file.c_str());
        }
        if (!s.ok()) {
            std::fprintf(stderr, "load_state: section is short\n");
            return false;
        }
    }
    if (!r.ok()) {
        std::fprintf(stderr, "load_state: %s is truncated\n", path.c_str());
        return false;
    }
    guest_env_ready_ = true;
    return true;
}

}  // namespace x86emu
