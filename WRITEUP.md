# picoCTF — JITFP

> **Flag:** `picoCTF{pr0cf5_d36ugg3r_bdb38627}`
>
> **Author:** syreal
> **Category:** Reverse Engineering / Pwn
> **Difficulty:** Medium

---

## Challenge

> If we can crack the password checker on this remote host, we will be able to
> infiltrate deeper into this criminal organization. The catch is it only
> functions properly on the host on which we found it.
>
> We have access to a periphery node on their network:
>
> ```
> ssh -p <PORT> ctf-player@dolphin-cove.picoctf.net
> ```

The home directory contains a single stripped, dynamically-linked, PIE x86-64
ELF (`ad7e550b`) built against `musl-libc`.

```
$ file ad7e550b
ad7e550b: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
          dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, stripped

$ ./ad7e550b A
================================v
*********************************
Incorrect
```

The program prints a header (`32 × '=' + 'v'`), then 33 stars (one per second),
then `Correct`/`Incorrect` and exits. Total runtime per attempt is ~34 s.

---

## Phase 1 — Reverse engineering

### 1.1 — A small army of one-character checkers

`objdump -d` on the binary reveals 65 nearly identical functions, each 29
bytes long, starting at `0x11d5`. Each one performs a single comparison:

```asm
0000000000001249 <fn_for_e>:
    1249: push   %rbp
    124a: mov    %rsp,%rbp
    124d: mov    %edi,%eax
    124f: mov    %al,-0x4(%rbp)
    1252: cmpb   $0x65, -0x4(%rbp)   ; 0x65 = 'e'
    1256: je     125f
    1258: mov    $0,%eax              ; mismatch → 0
    125d: jmp    1264
    125f: mov    $1,%eax              ; match    → 1
    1264: pop    %rbp
    1265: ret
```

`grep cmpb` confirms the 65 constants cover exactly:
`a–z` (26) + `A–Z` (26) + `0–9` (10) + `_` + `{` + `}` = **65 single-char checks**.

### 1.2 — Two tables driving the check

`main` is at `0x1982`. A simplified C-equivalent:

```c
int main(int argc, char **argv) {
    prctl(0x59616d61, -1, 0, 0, 0);                 // PR_SET_PTRACER, ANY

    if (argc != 2) { printf("Usage: %s <flag>\n", *argv); return 1; }

    for (i = 0; i < 32; i++) { putchar('='); fflush(stdout); }
    puts("v");

    for (i = 0; i <= 0x20; i++) {                    // 33 iterations
        sleep(1);
        idx = ((int  *) 0x4020)[i];                  // table1[i]
        fp  = ((void**) 0x4120)[idx];                // table2[idx]
        if (!fp(argv[1][i])) {                       // wrong char
            print_stars(0x21 - i);
            puts("Incorrect");
            return 1;
        }
        putchar('*'); fflush(stdout);
    }
    sleep(1);
    if (argv[1][0x21] != 0) { puts("Incorrect"); return 1; }   // exact length
    puts("Correct");
    return 0;
}
```

Two tables drive the check:

| Table  | VMA      | Section | Notes                                       |
|--------|----------|---------|---------------------------------------------|
| table1 | `0x4020` | `.data` | 33 × `int32` — fixed permutation of `0..32` |
| table2 | `0x4120` | `.bss`  | 33 × `void*` — **uninitialised at startup** |

`table1` (from `objdump -s -j .data`) is a permutation:

```
1e 16 0b 20 19 04 09 07 13 17 05 1a 12 1b 10 01
08 0f 02 0e 03 0d 18 15 0c 11 06 0a 1d 1c 14 1f 00
```

For each position `i` in the input, the binary calls
`table2[ table1[i] ]( argv[1][i] )`. Each char-checker only accepts one
specific byte, so the input character at position `i` must equal the byte
hard-coded in the function whose address sits at `table2[table1[i]]`.

The catch: **`table2` is in `.bss` and starts as 33 NULL pointers**. If the
binary were to run as-is, the very first call would be a `call *NULL` →
`SIGSEGV`. Yet the remote host runs it cleanly. So **something is populating
`table2` at runtime** — that "something" is the JIT-FP mechanism, and
recovering it is the puzzle.

### 1.3 — The `prctl` magic number

The first instruction in `main` is:

```c
prctl(0x59616d61, -1, 0, 0, 0);
```

`0x59616d61` is the **Yama** option `PR_SET_PTRACER`; the literal is the ASCII
"amaY" / "Yama" little-endian. `-1` is `PR_SET_PTRACER_ANY`.

Translation: *"any process running as this user is allowed to ptrace me."*

That is the binary's invitation to whatever helper is going to inject the
function pointers. On the boring host (our laptop) nobody is listening — the
binary calls a NULL pointer and dies. On the remote host, a helper is waiting.

---

## Phase 2 — Finding the helper

A quick `ps -ef` after logging in reveals it:

```
PID  USER     COMMAND
  1  root     /sbin/docker-init -- /opt/start.sh
  6  root     sshd: /usr/sbin/sshd -D -e -p 5555 …
  7  ctf-play python3 /root/jitfp-service.py
```

`/root/jitfp-service.py` is owned by root and unreadable, but it runs as
`ctf-player` — the same UID we get on the SSH shell.

Combined with the binary's `PR_SET_PTRACER_ANY` call, the design is now
obvious:

1. We launch `./ad7e550b <flag>`.
2. The binary tells the kernel "anyone same-UID may ptrace me".
3. The python service (also UID 1000) attaches and writes function pointers
   into our binary's `.bss` `table2` — **just-in-time** (hence **JITFP**:
   *Just-In-Time Function Pointers*).
4. Each iteration the service can rewrite `table2` with the correct pointer
   for **that** position, then let the binary run for one more step.

That last bullet is the key insight. The service does **not** populate
`table2` once with a permanent layout — it rewrites it every iteration.
A single-shot dump only reveals iteration 0's character.

---

## Phase 3 — Exploitation

Because we are the parent of `./ad7e550b` on our SSH shell, **we** also have
ptrace access to it. Anything ptrace can do, `/proc/<pid>/mem` can do too —
no compiled tooling required. The plan:

1. Spawn `./ad7e550b XXXX…` (33 placeholder bytes) so the program reaches the
   main loop.
2. Find the binary's PIE base from `/proc/<pid>/maps`.
3. During each of the 33 one-second sleep windows, snapshot
   `table2` from `/proc/<pid>/mem` at `base + 0x4120`.
4. For iteration `k`, the relevant entry is `table2[ table1[k] ]`. Compute its
   offset from base, look it up in our static table of char-checker offsets
   (`0x11d5 + i*0x1d → funcs_in_order[i]`), and append that char to the flag.

```python
import os, time, subprocess, struct

funcs_in_order = ("abcdefghijklmnopqrstuvwxyz"
                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "0123456789_{}")
char_funcs = {0x11d5 + i*0x1d: c for i, c in enumerate(funcs_in_order)}

table1 = [0x1e,0x16,0x0b,0x20,0x19,0x04,0x09,0x07,0x13,0x17,0x05,
          0x1a,0x12,0x1b,0x10,0x01,0x08,0x0f,0x02,0x0e,0x03,0x0d,
          0x18,0x15,0x0c,0x11,0x06,0x0a,0x1d,0x1c,0x14,0x1f,0x00]

p = subprocess.Popen(["./ad7e550b", "X"*33],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
start = time.time()

time.sleep(0.05)
with open(f"/proc/{p.pid}/maps") as f:
    base = int(next(l for l in f if "ad7e550b" in l).split("-")[0], 16)
table2 = base + 0x4120

def snap():
    fd = os.open(f"/proc/{p.pid}/mem", os.O_RDONLY)
    os.lseek(fd, table2, 0)
    data = os.read(fd, 33*8); os.close(fd)
    return struct.unpack("<33Q", data)

flag = ""
for k in range(33):
    while time.time() - start < k + 0.5:
        time.sleep(0.01)
    fp = snap()[table1[k]]
    flag += char_funcs[fp - base]
    print(f"  [{k:2d}] {flag}")

p.kill()
print(flag)
```

Run it on the remote host (the filesystem is read-only, so write to
`/dev/shm`):

```
$ cat solve.py | ssh -p $PORT ctf-player@dolphin-cove.picoctf.net \
        "cat > /dev/shm/solve.py && python3 /dev/shm/solve.py"

[+] PID=34  base=0x568f01331000
  iter  0 t= 0.51 idx=30 -> p
  iter  1 t= 1.51 idx=22 -> i
  iter  2 t= 2.51 idx=11 -> c
  iter  3 t= 3.50 idx=32 -> o
  iter  4 t= 4.51 idx=25 -> C
  iter  5 t= 5.50 idx= 4 -> T
  iter  6 t= 6.51 idx= 9 -> F
  iter  7 t= 7.51 idx= 7 -> {
  iter  8 t= 8.50 idx=19 -> p
  iter  9 t= 9.50 idx=23 -> r
  iter 10 t=10.51 idx= 5 -> 0
  iter 11 t=11.51 idx=26 -> c
  iter 12 t=12.51 idx=18 -> f
  iter 13 t=13.50 idx=27 -> 5
  iter 14 t=14.50 idx=16 -> _
  iter 15 t=15.51 idx= 1 -> d
  iter 16 t=16.51 idx= 8 -> 3
  iter 17 t=17.51 idx=15 -> 6
  iter 18 t=18.50 idx= 2 -> u
  iter 19 t=19.50 idx=14 -> g
  iter 20 t=20.51 idx= 3 -> g
  iter 21 t=21.51 idx=13 -> 3
  iter 22 t=22.50 idx=24 -> r
  iter 23 t=23.50 idx=21 -> _
  iter 24 t=24.51 idx=12 -> b
  iter 25 t=25.51 idx=17 -> d
  iter 26 t=26.50 idx= 6 -> b
  iter 27 t=27.50 idx=10 -> 3
  iter 28 t=28.50 idx=29 -> 8
  iter 29 t=29.51 idx=28 -> 6
  iter 30 t=30.51 idx=20 -> 2
  iter 31 t=31.50 idx=31 -> 7
  iter 32 t=32.50 idx= 0 -> }

[+] FLAG: picoCTF{pr0cf5_d36ugg3r_bdb38627}
```

Confirm:

```
$ ./ad7e550b 'picoCTF{pr0cf5_d36ugg3r_bdb38627}'
================================v
*********************************
Correct
```

The flag's body, `pr0cf5_d36ugg3r`, is a wink at the technique itself —
**procfs debugger**. The author left the technique baked into the answer.

---

## Lessons learned

- **`/proc/<pid>/mem` is a fully-functional debugger** if you have ptrace
  permission on the target. No `gdb`, no compiler, no kernel module required.
- `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` is a **trust boundary** — once
  a process executes it, any same-UID process can read or modify it. It's
  used legitimately by crash handlers (e.g. Chrome) but is also a perfect
  hook for an out-of-process JIT/anti-tamper helper, as `JITFP` demonstrates.
- A one-shot memory dump is not enough when the helper is rewriting state
  per iteration. **Sample at the right moment** — here, mid-sleep — and the
  state is captured deterministically.
- The 1-second `sleep` between iterations is not "anti-brute-force"; it is
  the *exploitation primitive*. It gives the helper (and us) a stable
  one-second window to act in.
- Stripped binaries with hundreds of near-identical functions are an
  enumeration problem, not an analysis problem. The 65 functions in `JITFP`
  follow a strict 29-byte stride keyed by ASCII order — recognising the
  stride collapses the whole reverse-engineering step to a one-line dict
  comprehension.

---

## Appendix — Indicators in the binary

| Item                                | Address    | Notes                              |
|-------------------------------------|------------|------------------------------------|
| First char-checker (`'a'`)          | `0x11d5`   | 29-byte stride                     |
| Last char-checker  (`'}'`)          | `0x1918`   | 65th function                      |
| `print_stars(n)` helper             | `0x1932`   | `putchar('*'); fflush; sleep(1)`   |
| `main`                              | `0x1982`   |                                    |
| `prctl(PR_SET_PTRACER, ANY)`        | `0x19a8`   | First instruction in `main`        |
| `call *table2[idx]`                 | `0x1a7d`   | The JIT call site                  |
| `table1` (permutation, 33 × i32)    | `0x4020`   | `.data`, fixed                     |
| `table2` (function ptrs, 33 × ptr)  | `0x4120`   | `.bss`, written by the helper      |
