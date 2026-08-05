"""Finds where our syscall trace first diverges from qemu's -strace."""
import re
import sys

NAMES = {
    0: 'read', 1: 'write', 2: 'open', 3: 'close', 4: 'stat', 5: 'fstat', 6: 'lstat',
    8: 'lseek', 9: 'mmap', 10: 'mprotect', 11: 'munmap', 12: 'brk', 13: 'rt_sigaction',
    14: 'rt_sigprocmask', 16: 'ioctl', 17: 'pread64', 18: 'pwrite64', 19: 'readv',
    20: 'writev', 21: 'access', 22: 'pipe', 25: 'mremap', 28: 'madvise', 32: 'dup',
    33: 'dup2', 39: 'getpid', 56: 'clone', 57: 'fork', 58: 'vfork', 59: 'execve',
    60: 'exit', 61: 'wait4', 62: 'kill', 63: 'uname', 72: 'fcntl', 77: 'ftruncate',
    79: 'getcwd', 80: 'chdir', 81: 'fchdir', 82: 'rename', 87: 'unlink', 89: 'readlink',
    97: 'getrlimit', 102: 'getuid', 104: 'getgid', 107: 'geteuid', 108: 'getegid',
    110: 'getppid', 131: 'sigaltstack', 137: 'statfs', 158: 'arch_prctl', 186: 'gettid',
    201: 'time', 202: 'futex', 204: 'sched_getaffinity', 217: 'getdents64',
    218: 'set_tid_address', 228: 'clock_gettime', 231: 'exit_group', 257: 'openat',
    262: 'newfstatat', 263: 'unlinkat', 269: 'faccessat', 273: 'set_robust_list',
    292: 'dup3', 293: 'pipe2', 302: 'prlimit64', 318: 'getrandom', 334: 'rseq',
}


def ours(path):
    out = []
    for line in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'\[sys\] (\d+)\(([^)]*)\) = (-?\d+)', line)
        if m:
            nr = int(m.group(1))
            out.append((NAMES.get(nr, 'sys%d' % nr), m.group(2), m.group(3)))
    return out


def theirs(path):
    out = []
    for line in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'\s*\d+ ([a-z_0-9]+)\((.*)\)\s*=\s*(\S+)', line)
        if m:
            out.append((m.group(1), m.group(2), m.group(3)))
    return out


a = ours(sys.argv[1])
b = theirs(sys.argv[2])
print('ours %d calls, reference %d calls' % (len(a), len(b)))
for i in range(min(len(a), len(b))):
    if a[i][0] != b[i][0]:
        print('first divergence in the call *sequence* at index %d' % i)
        for j in range(max(0, i - 5), min(len(a), i + 5)):
            mark = '>>' if j == i else '  '
            print('%s ours[%d] %s(%s) = %s' % (mark, j, a[j][0], a[j][1], a[j][2]))
        for j in range(max(0, i - 5), min(len(b), i + 5)):
            mark = '>>' if j == i else '  '
            print('%s ref [%d] %s(%s) = %s' % (mark, j, b[j][0], b[j][1], b[j][2]))
        break
else:
    print('the shared prefix agrees on every call name (%d calls)' %
          min(len(a), len(b)))
    n = min(len(a), len(b))
    print('ours continues:', [c[0] for c in a[n:n + 8]])
    print('ref continues: ', [c[0] for c in b[n:n + 8]])
