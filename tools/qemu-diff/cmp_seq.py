"""Finds the first place our execution order stops containing the reference's.

qemu logs the start of each translation block it runs, and where those blocks
begin depends on how it happened to translate the code - so its stream is a
*subsequence* of the addresses actually executed, not a list of every one.  We
log every execution of any address qemu ever used as a block start.  Therefore
qemu's stream must appear inside ours, in order.  The first qemu entry we cannot
find within a short window is the moment we went somewhere it never went.
"""
import struct
import sys

ours_path, theirs_path = sys.argv[1], sys.argv[2]
WINDOW = 100000
CONTEXT = 16


def ours_stream(path):
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8 * 65536)
            if not chunk:
                return
            for (v,) in struct.iter_unpack('<Q', chunk):
                yield v


def theirs_stream(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                yield int(line, 16)


ours = ours_stream(ours_path)
recent = []
matched = 0
for want in theirs_stream(theirs_path):
    skipped = []
    while True:
        got = next(ours, None)
        if got is None:
            print('our run ended after matching %d reference blocks' % matched)
            print('  it was looking for %012X' % want)
            print('  last addresses we executed:')
            for v in recent[-CONTEXT:]:
                print('    %012X' % v)
            sys.exit(0)
        recent.append(got)
        if len(recent) > CONTEXT * 4:
            del recent[:CONTEXT]
        if got == want:
            matched += 1
            break
        skipped.append(got)
        if len(skipped) > WINDOW:
            print('diverged after matching %d reference blocks' % matched)
            print('  the reference went to %012X; we did not, within %d blocks' %
                  (want, WINDOW))
            print('  we executed instead:')
            for v in skipped[:CONTEXT]:
                print('    %012X' % v)
            print('  (context before: %s)' %
                  ' '.join('%X' % v for v in recent[:CONTEXT]))
            sys.exit(0)
print('the whole reference stream appears in ours, in order (%d blocks)' % matched)
