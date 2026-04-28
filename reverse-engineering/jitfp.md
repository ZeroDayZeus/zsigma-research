# Just-In-Time Function Pointer Injection: A Reverse Engineering Case Study

> **Focus:** Reverse Engineering, Runtime Memory Analysis, Linux `ptrace`, `/proc/<pid>/mem`  
> **Environment:** Linux x86-64, PIE ELF, musl-libc  
> **Difficulty:** Advanced  
> **Author:** zSigma Research  

---

## Executive Summary

This case study analyzes a Linux x86-64 executable that implements a deliberately unusual validation mechanism based on runtime function pointer injection.

At first glance, the binary appears to contain all the logic required to validate an input string. Static analysis reveals a large set of one-character checker functions and a fixed permutation table. However, the function pointer table used by the validation routine is stored in `.bss` and is empty at process startup.

The binary only works correctly in its intended runtime environment because an external same-UID helper process attaches to it and writes valid function pointers into memory just before they are used.

The key insight is that the same trust boundary used by the helper can also be used by an analyst. By reading `/proc/<pid>/mem` during predictable one-second sleep windows, it is possible to snapshot the runtime function pointer table, identify the checker selected for each input position, and reconstruct the expected input deterministically.

This is a practical example of why runtime state must be treated as part of the reverse engineering target, especially when a binary deliberately delegates part of its behavior to an external process.

---

## Table of Contents

- [1. Target Overview](#1-target-overview)
- [2. Initial Behavior](#2-initial-behavior)
- [3. Static Analysis](#3-static-analysis)
  - [3.1 One-character checker functions](#31-one-character-checker-functions)
  - [3.2 The validation routine](#32-the-validation-routine)
  - [3.3 Static tables](#33-static-tables)
- [4. Runtime Anomaly](#4-runtime-anomaly)
- [5. The `prctl` Trust Boundary](#5-the-prctl-trust-boundary)
- [6. External Runtime Helper](#6-external-runtime-helper)
- [7. Exploitation Strategy](#7-exploitation-strategy)
- [8. Implementation](#8-implementation)
- [9. Result](#9-result)
- [10. Security Takeaways](#10-security-takeaways)
- [Appendix A - Important Binary Offsets](#appendix-a---important-binary-offsets)
- [Appendix B - Permutation Table](#appendix-b---permutation-table)

---

## 1. Target Overview

The target is a stripped, dynamically linked, PIE x86-64 ELF executable built against `musl-libc`.

```txt
$ file ad7e550b
ad7e550b: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
          dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, stripped
```

Relevant properties:

| Property | Value |
|---|---|
| Architecture | x86-64 |
| Format | ELF |
| Linking | Dynamically linked |
| PIE | Enabled |
| Symbols | Stripped |
| libc | musl-libc |
| Main technique | Runtime function pointer injection |

The executable expects a single command-line argument and validates it one character at a time.

---

## 2. Initial Behavior

A basic execution with an invalid input produces a progress indicator and then exits with an incorrect result.

```txt
$ ./ad7e550b A
================================v
*********************************
Incorrect
```

The observable behavior is:

- the program prints 32 `=` characters;
- then it prints `v`;
- then it prints 33 stars, one per second;
- finally it prints either `Correct` or `Incorrect`.

The runtime is approximately 34 seconds per attempt.

This delay is important. It is not only a slowdown mechanism; it provides a stable observation window during execution.

---

## 3. Static Analysis

### 3.1 One-character checker functions

Disassembly reveals 65 small functions, each 29 bytes long, starting at offset `0x11d5`.

Each function accepts one byte and returns whether it matches a hardcoded character.

Example checker for the character `e`:

```asm
0000000000001249 <checker_for_e>:
    1249: push   %rbp
    124a: mov    %rsp,%rbp
    124d: mov    %edi,%eax
    124f: mov    %al,-0x4(%rbp)
    1252: cmpb   $0x65, -0x4(%rbp)   ; 0x65 = 'e'
    1256: je     125f
    1258: mov    $0,%eax              ; mismatch -> 0
    125d: jmp    1264
    125f: mov    $1,%eax              ; match -> 1
    1264: pop    %rbp
    1265: ret
```

The checker functions cover the following alphabet:

```txt
abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ
0123456789
_
{
}
```

The layout is regular:

```txt
first checker: 0x11d5
stride:        0x1d bytes
count:         65 functions
```

This makes it possible to map checker function offsets back to accepted characters:

```python
FUNCS_IN_ORDER = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_{}"
)

CHAR_FUNCS = {
    0x11D5 + i * 0x1D: c
    for i, c in enumerate(FUNCS_IN_ORDER)
}
```

---

### 3.2 The validation routine

The main validation routine is located at offset `0x1982`.

A simplified C-equivalent of the relevant logic is:

```c
int main(int argc, char **argv) {
    prctl(0x59616d61, -1, 0, 0, 0);

    if (argc != 2) {
        printf("Usage: %s <input>\n", *argv);
        return 1;
    }

    for (int i = 0; i < 32; i++) {
        putchar('=');
        fflush(stdout);
    }

    puts("v");

    for (int i = 0; i <= 0x20; i++) {
        sleep(1);

        int idx = ((int *)0x4020)[i];
        int (*fp)(char) = ((void **)0x4120)[idx];

        if (!fp(argv[1][i])) {
            print_stars(0x21 - i);
            puts("Incorrect");
            return 1;
        }

        putchar('*');
        fflush(stdout);
    }

    sleep(1);

    if (argv[1][0x21] != 0) {
        puts("Incorrect");
        return 1;
    }

    puts("Correct");
    return 0;
}
```

The input is checked over 33 positions. After that, the program verifies that the input terminates exactly at byte `0x21`, enforcing a length of 33 characters.

---

### 3.3 Static tables

Two tables drive the validation process.

| Table | Address | Section | Purpose |
|---|---:|---|---|
| `table1` | `0x4020` | `.data` | Fixed permutation of indices |
| `table2` | `0x4120` | `.bss` | Runtime function pointer table |

The validation routine computes:

```c
table2[table1[i]](argv[1][i])
```

Therefore, for each input position `i`, the expected character depends on the function pointer stored at:

```txt
table2[table1[i]]
```

The fixed permutation table is:

```txt
1e 16 0b 20 19 04 09 07 13 17 05 1a 12 1b 10 01
08 0f 02 0e 03 0d 18 15 0c 11 06 0a 1d 1c 14 1f 00
```

---

## 4. Runtime Anomaly

The most important observation is that `table2` is stored in `.bss`.

Objects in `.bss` are zero-initialized at process startup. Therefore, `table2` initially contains null pointers.

If the binary were executed without external intervention, the first indirect call would be equivalent to:

```c
NULL(argv[1][0])
```

This should result in a segmentation fault.

However, in the intended runtime environment, the binary executes normally.

This implies that another component populates `table2` dynamically while the process is running.

The binary is not self-contained. Its complete behavior only exists at runtime.

---

## 5. The `prctl` Trust Boundary

The first significant call in the validation routine is:

```c
prctl(0x59616d61, -1, 0, 0, 0);
```

The value `0x59616d61` corresponds to `PR_SET_PTRACER`, part of Linux Yama ptrace controls.

The second argument, `-1`, corresponds to `PR_SET_PTRACER_ANY`.

In practical terms, the process explicitly allows same-UID processes to trace it.

This is the core trust boundary:

```txt
Any same-UID process can attach to the target and inspect or modify its memory.
```

This behavior can be legitimate in some contexts, such as crash handlers or debugging infrastructure. In this case, it also enables a runtime helper to modify the validation state externally.

From an analyst’s perspective, the same mechanism provides a path to observe the injected state.

---

## 6. External Runtime Helper

Process enumeration in the target environment reveals a same-UID Python service:

```txt
PID  USER        COMMAND
1    root        /sbin/docker-init -- /opt/start.sh
6    root        sshd: /usr/sbin/sshd -D -e -p 5555 ...
7    ctf-player  python3 /root/jitfp-service.py
```

The helper script is unreadable, but its execution context is enough to explain the observed behavior.

The likely runtime model is:

1. The target process starts.
2. It calls `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)`.
3. The helper process attaches to it.
4. The helper writes function pointers into `table2`.
5. The target calls the injected pointer for the current validation step.

A crucial detail is that the helper does not need to populate the entire table permanently.

It can rewrite the table before each iteration.

This means a single memory snapshot may capture only one moment in the validation sequence. To reconstruct the entire expected input, repeated sampling is required.

---

## 7. Exploitation Strategy

The one-second sleep before each character check provides a reliable observation window.

The strategy is:

1. Launch the binary with a 33-byte placeholder input.
2. Read the process memory map from `/proc/<pid>/maps`.
3. Extract the PIE base address of the executable.
4. Compute the runtime address of `table2`:

```txt
table2_runtime = pie_base + 0x4120
```

5. During each sleep window, read 33 pointers from `/proc/<pid>/mem`.
6. Select the pointer used by the current iteration:

```txt
function_pointer = table2[table1[i]]
```

7. Convert it back to a binary-relative offset:

```txt
function_offset = function_pointer - pie_base
```

8. Map the function offset to the corresponding one-character checker.
9. Append the recovered character to the expected input.

This avoids brute force entirely. The expected input is recovered from runtime state.

---

## 8. Implementation

```python
import os
import time
import struct
import subprocess


FUNCS_IN_ORDER = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_{}"
)

CHAR_FUNCS = {
    0x11D5 + i * 0x1D: c
    for i, c in enumerate(FUNCS_IN_ORDER)
}

TABLE1 = [
    0x1E, 0x16, 0x0B, 0x20, 0x19, 0x04, 0x09, 0x07,
    0x13, 0x17, 0x05, 0x1A, 0x12, 0x1B, 0x10, 0x01,
    0x08, 0x0F, 0x02, 0x0E, 0x03, 0x0D, 0x18, 0x15,
    0x0C, 0x11, 0x06, 0x0A, 0x1D, 0x1C, 0x14, 0x1F,
    0x00,
]

BINARY = "./ad7e550b"
PLACEHOLDER = "X" * 33

TABLE2_OFFSET = 0x4120
TABLE2_ENTRIES = 33


def get_pie_base(pid: int) -> int:
    maps_path = f"/proc/{pid}/maps"

    with open(maps_path, "r", encoding="utf-8") as maps:
        for line in maps:
            if "ad7e550b" in line:
                return int(line.split("-")[0], 16)

    raise RuntimeError("PIE base not found")


def read_table2(pid: int, table2_addr: int) -> tuple[int, ...]:
    mem_path = f"/proc/{pid}/mem"

    fd = os.open(mem_path, os.O_RDONLY)

    try:
        os.lseek(fd, table2_addr, os.SEEK_SET)
        data = os.read(fd, TABLE2_ENTRIES * 8)
    finally:
        os.close(fd)

    if len(data) != TABLE2_ENTRIES * 8:
        raise RuntimeError("Could not read the full table2 memory region")

    return struct.unpack("<33Q", data)


def main() -> None:
    process = subprocess.Popen(
        [BINARY, PLACEHOLDER],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    start = time.time()

    try:
        time.sleep(0.05)

        base = get_pie_base(process.pid)
        table2_addr = base + TABLE2_OFFSET

        print(f"[+] PID:      {process.pid}")
        print(f"[+] PIE base: {hex(base)}")
        print(f"[+] table2:   {hex(table2_addr)}")
        print()

        recovered = ""

        for i in range(33):
            while time.time() - start < i + 0.5:
                time.sleep(0.01)

            table2 = read_table2(process.pid, table2_addr)

            index = TABLE1[i]
            function_pointer = table2[index]
            function_offset = function_pointer - base

            recovered_char = CHAR_FUNCS[function_offset]
            recovered += recovered_char

            print(
                f"iter {i:02d} | "
                f"idx={index:02d} | "
                f"fp={hex(function_pointer)} | "
                f"offset={hex(function_offset)} | "
                f"char={recovered_char!r} | "
                f"recovered={recovered}"
            )

        print()
        print(f"[+] Recovered input: {recovered}")

    finally:
        process.kill()


if __name__ == "__main__":
    main()
```

If the filesystem is restricted, the solver can be copied to an in-memory location such as `/dev/shm` and executed from there:

```txt
cat solve.py | ssh -p <PORT> user@remote-host \
  "cat > /dev/shm/solve.py && python3 /dev/shm/solve.py"
```

---

## 9. Result

The runtime snapshots reveal the expected input one character at a time.

Example output:

```txt
[+] PID:      34
[+] PIE base: 0x568f01331000
[+] table2:   0x568f01335120

iter 00 | idx=30 | char='p' | recovered=p
iter 01 | idx=22 | char='i' | recovered=pi
iter 02 | idx=11 | char='c' | recovered=pic
iter 03 | idx=32 | char='o' | recovered=pico
iter 04 | idx=25 | char='C' | recovered=picoC
iter 05 | idx=04 | char='T' | recovered=picoCT
iter 06 | idx=09 | char='F' | recovered=picoCTF
iter 07 | idx=07 | char='{' | recovered=picoCTF{
...
iter 32 | idx=00 | char='}' | recovered=picoCTF{pr0cf5_d36ugg3r_bdb38627}
```

The recovered input is:

```txt
picoCTF{pr0cf5_d36ugg3r_bdb38627}
```

Validation confirms the result:

```txt
$ ./ad7e550b 'picoCTF{pr0cf5_d36ugg3r_bdb38627}'
================================v
*********************************
Correct
```

The string body, `pr0cf5_d36ugg3r`, is also descriptive of the technique: a procfs-based debugger.

---

## 10. Security Takeaways

This case study highlights several important security lessons.

### Runtime state is part of the attack surface

Static analysis alone showed an incomplete picture. The decisive validation state was injected dynamically after process startup.

When analyzing protected binaries, runtime memory should be treated as a primary source of truth.

### `PR_SET_PTRACER_ANY` weakens process isolation

Allowing same-UID processes to trace a target may be necessary for legitimate tooling, but it changes the trust boundary.

Once enabled, same-UID processes may be able to inspect or modify sensitive runtime state.

### `/proc/<pid>/mem` can function as a debugger

If ptrace permissions allow it, reading `/proc/<pid>/mem` provides direct access to process memory without requiring `gdb`, a compiler, or a custom native tool.

### Delays can become exploitation windows

The one-second sleep between iterations looks like a slowdown mechanism, but it also creates a stable window for memory observation.

Timing behavior can unintentionally make runtime attacks easier to synchronize.

### Dynamic mutation defeats one-shot dumping

A single memory snapshot can be misleading when another process rewrites state repeatedly.

Repeated sampling at semantically meaningful points in execution can reveal the intended logic.

---

## Appendix A - Important Binary Offsets

| Item | Address | Notes |
|---|---:|---|
| First char-checker, `'a'` | `0x11d5` | 29-byte stride |
| Last char-checker, `'}'` | `0x1918` | 65th function |
| `print_stars(n)` helper | `0x1932` | Prints `*`, flushes, sleeps |
| Main validation routine | `0x1982` | Input validation logic |
| `prctl(PR_SET_PTRACER, ANY)` | `0x19a8` | Enables same-UID tracing |
| Indirect call site | `0x1a7d` | `call *table2[idx]` |
| `table1` | `0x4020` | Fixed permutation |
| `table2` | `0x4120` | Runtime function pointer table |

---

## Appendix B - Permutation Table

Raw table bytes:

```txt
1e 16 0b 20 19 04 09 07 13 17 05 1a 12 1b 10 01
08 0f 02 0e 03 0d 18 15 0c 11 06 0a 1d 1c 14 1f 00
```

Expanded Python representation:

```python
TABLE1 = [
    0x1E, 0x16, 0x0B, 0x20, 0x19, 0x04, 0x09, 0x07,
    0x13, 0x17, 0x05, 0x1A, 0x12, 0x1B, 0x10, 0x01,
    0x08, 0x0F, 0x02, 0x0E, 0x03, 0x0D, 0x18, 0x15,
    0x0C, 0x11, 0x06, 0x0A, 0x1D, 0x1C, 0x14, 0x1F,
    0x00,
]
```

---

## Final Note

The interesting aspect of this sample is that the apparent static validation mechanism is intentionally incomplete.

The decisive function pointer table exists only as runtime state, written by an external helper process through a permissive ptrace boundary. Once that design is recognized, the problem becomes a controlled runtime memory observation exercise rather than a brute-force or symbolic execution task.
