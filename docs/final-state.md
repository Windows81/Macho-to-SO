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

## Namespace experiment (2026-11-27)

Renamed Studio's 287 `std::__1` imports to `std::__ndk1` with LIEF, plus
`__mbstate_t` mangling fixes, reverting one Qtitan symbol whose provider is not
libc++. All renamed imports resolve against `libc++_shared.so`. Added
`libc++_shared.so` as NEEDED to both Studio images and removed the bridge's
no-op `__cxa_*` stubs so Android's exception ABI is used.

Verified: `register QtNative -> 0`, `qt initJNI retry -> 0`, `singleton state
7`, `launching Studio`, then `fault sig 11 addr 0x51 pc_va 0x203a915f0`. The
faulting call is `__cxa_throw`; the exception object pointer is the small value
0x51. LIEF shifted the image by 0x1000, so the hand-written `main` wrapper was
rewritten at its new offset with corrected constants.

Verdict: the namespace and layout theory was correct — Qt initialises and
Studio starts cleanly — but a small tagged/rebased value reaches exception
handling. That is the remaining blocker.

### Exception-field repair (2026-11-27)

With the namespace rename and real libc++ exception ABI active, the thrown
object's first field held 0x51 while its other fields were valid pointers.
Replacing that field (and any matching register) with the typeinfo passed as
the second argument let execution continue:

```
RobloxPortProxy: repaired exception field 0x51 -> 0x7675192476
RobloxPortDiag: fault sig 11 addr 0x31 pc_va 0x203a915f0
RobloxPortProxy: repaired exception field 0x31 -> 0x7675192476
```

The next faults at 0x31 and 0x8 are further small values in other paths. No
window yet. The repair is parameterised as proxyFix=4 and is not a permanent
fix.

### C-runtime and proxy findings (2026-11-27)

Routing `snprintf`, `strlen`, `atoi`, `pthread_self` and other ordinary C
functions to bionic removed the `0x51` exception fault entirely; those calls
were returning zero through Java. After that, the remaining faults are a
chain of small tagged values (`0x31`) followed by tagged pointers in x0 and
then null dereferences. Redirecting a bad pointer to a zeroed proxy page
advances a few instructions but the next load returns zero, so execution
faults again on null. A typed proxy factory is needed; no window yet.

### Typed proxy factory (2026-11-27)

A vtable-bearing proxy object was supplied per fault (fresh and stable-map
variants). Fresh proxies produced 60+ intercepts in milliseconds; the stable
map hit the 512-intercept cap with three repeating PCs. The process still died
with no Studio window and no popup window. The tagged values live in a
container Studio iterates, so the next real step is fixing that container's
producer rather than expanding the fault handler.

### Producer-side attempt (2026-11-27)

Disassembly of the repeating PCs showed a large cleanup routine loading local
objects from stack slots (`sp+0x1c0` onward) and calling virtual destructors
through `ldr x8,[x0]; ldr x8,[x8,#8]; blr x8`. The slots held small tagged
values. Bounded stack patching produced 495 intercepts with the same three
PCs repeating; the values are regenerated each iteration. No Studio window or
popup was observed. The remaining work is to fix the producer of these values
in the converted image, not the fault handler.

### Cleanup-slot patch loop (2026-11-27)

An automated loop NOPed the faulting instruction in the Studio cleanup routine
and rebuilt/reinstalled each time. The fault advanced from 0x31 to 0x38, then
to 0x4c, then to 0x636e6174736e49 (ASCII "Instanc" used as a pointer), at
which point the fault PC left the Studio image. No Studio window, Qt setup
marker, or popup window appeared in any iteration.

### String-as-pointer faults in bionic (2026-11-27)

The fault PC was inside bionic libc's Scudo allocator, called with ASCII type
names ("Instance", "Depende...") as pointers. The diagnostic was itself
faulting while dumping those registers; after guarding the dump, proxyFix=2
intercepted the values but the zeroed proxy page is not a valid Scudo chunk
header. No marker, Studio window or popup was observed.

### Free-stub filter (2026-11-27)

A tagged-pointer guard on the bridge's exported `free` symbol logged zero
calls; the fault still occurred in bionic Scudo with "Instance" as the pointer.
The bad pointer is freed by bionic's own cleanup path, not through the JNI
stub boundary. No Studio window, marker or popup was observed.

### ABI limit confirmed (2026-11-27)

Verification: 286/286 renamed Studio imports resolve to Android's libc++;
the bridge's 291 `std::__1` stubs are no longer used. The persistent
ASCII-as-pointer faults ("Instance", "Depende...") therefore originate in
inlined string field accesses inside Studio, which were compiled against Apple's
layout and read Android-layout objects. This is a link-level unfixable ABI
mismatch; the only complete remedy is rebuilding Studio against the Android
libc++ ABI.

### Heap-proxy attempt (2026-11-27)

A SIGSEGV mode that substituted a real bionic allocation for the ASCII
type-name pointer logged two intercepts and then died, with no marker, Studio
window or popup. This rules out a simple allocator-header problem and
confirms the inlined ABI mismatch as the fundamental blocker.

### strlen-boundary attempt (2026-11-27)

Decoding the exact fault PC showed `__strlen_aarch64` in bionic libc doing
`ldp x2,x3,[x0]` with x0 = the ASCII bytes of "Instance". A tagged-pointer
guard on the exported `strlen` symbol logged zero calls because libc calls its
internal implementation directly. No marker, Studio window or popup appeared.

### Snprintf-boundary attempt (2026-11-27)

A vararg filter on `snprintf` that converts tagged/inline-ASCII arguments to
temporary strings logged zero calls; the fault persisted in bionic internal
strlen with "Instance" as the pointer. This closes the exported-symbol route:
free, strlen and snprintf filters all failed for the same reason.
