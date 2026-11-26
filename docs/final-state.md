# Roblox Studio Android port — final state (2026-11-26)

## Deliverable: complete

The three requested transformations are implemented, verified and published:

- 25/25 Mach-O images converted to AArch64 ELF shared objects.
- 7,146 Qt symbols rebound to Android Qt equivalents.
- 9,921 macOS system calls replaced with JNI stubs.
- Repositories: `Windows81/Macho-to-SO` (v0.1.2), `Windows81/MacOS-JNI-Stubs`,
  `Windows81/Qt-Android-Rebind`.
- `Windows81/Qt-Window-Demo` holds a verified Qt-for-Android fallback window.

Evidence: `out/c5c97d45b6614310/reports/summary.json`.

## Working window

The main port APK includes `.QtWindowActivity`, verified live:

```text
I/QtWindowDemo: QApplication constructed
I/QtWindowDemo: QLabel shown; entering QApplication::exec()
Window #24 Window{cee3390 u0 io.github.robloxport/.QtWindowActivity}
  mHasSurface=true isReadyForDisplay()=true
  mDrawState=HAS_DRAWN
  isOnScreen=true isVisible=true
```

Screenshot: `/tmp/opencode/qtwindow-integrated.png` — large red "Roblox"
rendered by Qt on the right pane, plainly legible.

## Remaining blocker: Studio's own GUI

Qt starts correctly in Studio mode (`qt initJNI retry -> 0`) and Java calls
`launchStudio()`, but Studio crash-loops before Qt setup. `markerStatus`
stays 0. Fuzz winner: `tagSkip=1, proxyFix=0, stringFix=0`.

Exact fault with `proxyFix=0`:

```text
fault sig 11 addr 0x31 pc_va 0x2026f7158
fault insn 0x3c830140     ; stur q0, [x10, #48], so x10 = 1
x8 = x9 = 0xaee28b6c71a75147   ; macOS ARM64e tagged pointer
```

With `proxyFix=1` the handler intercepts that fault:

```text
RobloxPortProxy: intercept pc ... insn 0x3dc000a0 reg x5 old 0 addr 0 -> proxy
fault sig 11 addr 0 pc_va 0xffffff881b885000
```

so one bad value is replaced but the next fault has a bogus PC. The defect is
systemic: macOS tagged-pointer and libc++ string values are baked into static
data and produced at runtime, and Android has no runtime that decodes them.

Fixes tried and retained in the source: native bionic heap, real
`mmap`/`mprotect` syscalls, native `__next_prime`, native mimalloc internals,
ARM64 x8 aggregate returns, tagged-pointer rebase skipping in the converter
(130,754 relocations dropped), and the SIGSEGV proxy handler.

## Verdict

Studio's full GUI is not reachable with the current compatibility layer.
Everything else is finished and published, and a working Qt window is
available in the port APK.

## Late finding (20:20 UTC): the fault is inside the initializer prologue

Instrumented run with `proxyFix=3`, `tagSkip=1`, `stringFix=0`:

```text
fault insn 0x3c830140 at pc 0x79efa05158   ; stur q0, [x10, #48], x10 = 1
RobloxPortProxy: intercept ... reg x10 old 0x1 addr 0x31 -> proxy
fault insn 0xf940204b at pc 0x79efa0515c   ; ldr x11, [x2, #0x40], x2 = 0
fault insn 0xf804014b at pc 0x79efa05160   ; str x11, [x10, #0x10]
fault insn 0xa903fc5f at pc 0x79efa05164   ; stp x3, x4, [x2, #...]
fault insn 0x3dc00060 at pc 0x79efa05174
fault insn 0x3dc000a0 at pc 0x79efa051a4
fault sig 11 addr 0 pc_va 0xffffff8812cf2000   ; bogus PC after proxy resumes
```

Every base register in the first ten instructions of the STM initialiser
holds a small integer or zero. Replacing those registers with proxy pages
lets execution continue for a few instructions and then jumps to a bogus PC.
No stub returns a tagged value (`RobloxPortTag` logged nothing), so the
values come from the converted static data and the rebasing model itself.
This is a hard blocker in the artefact.
