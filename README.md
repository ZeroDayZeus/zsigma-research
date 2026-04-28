<p align="center">
  <a href="https://www.zsigma.ai">
   <img src="./assets/logo.png" alt="zSigma logo" width="180">
  </a>
</p>

<h1 align="center">zSigma Research</h1>

<p align="center">
  Technical research notes, reverse engineering case studies, and security analysis.
</p>

<p align="center">
  <a href="https://www.zsigma.ai"><strong>Website</strong></a>
  ·
  <a href="https://www.zsigma.ai/#contact"><strong>Contact</strong></a>
</p>

---

## Research Archive

### Reverse Engineering

| Title | Focus |
|---|---|
| [Just-In-Time Function Pointer Injection](./reverse-engineering/jitfp.md) | Runtime memory analysis, Linux `ptrace`, `/proc/<pid>/mem`, PIE ELF |

### Binary Exploitation

| Title | Focus |
|---|---|
| [Heap Havoc – Heap-Based Function Pointer Hijacking](./binary-exploitation/heap-havoc/) | Heap overflow analysis, function pointer corruption, control-flow redirection |

---

## Repository Structure

```txt
reverse-engineering/
  jitfp.md

binary-exploitation/
  README.md
  heap-havoc/
    README.md
    exploit.py
    vuln.c
    notes.md
```
