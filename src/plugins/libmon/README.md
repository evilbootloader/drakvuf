# libmon

Logs calls to chosen exported functions in shared objects loaded by a Linux
guest process, with their arguments and return values. It is the Linux
counterpart to `apimon`, which does the same for Windows DLLs.

```
drakvuf -r profile.json -d guest -a libmon \
        --so-hooks-list src/plugins/libmon/example/so-hooks-list-glibc-x86_64
```

## Hook list

One function per line, same grammar as apimon's `--dll-hooks-list`:

```
<so name>,<function name|hex offset>[,no-retval],<log|log+stack>[,<arg>,...]
```

The `<so name>` matches a prefix of the basename of the mapped path, so
`libc.so.6` matches `/lib/x86_64-linux-gnu/libc.so.6`, and `libssl.so` also
matches a versioned `libssl.so.3`. Matching is case-sensitive, unlike the
Windows equivalent. A pattern containing `/` matches a path suffix instead.

Each `<arg>` is `[Name:]type`. Only some types change formatting — `lpcstr`
reads a NUL-terminated string, `pulong`/`pulonglong` dereference a pointer —
and any other name simply documents the signature while the raw value is
printed. The printers are shared with apimon.

## Options

| Option | Effect |
| --- | --- |
| `--so-hooks-list <file>` | the hook list; without it the plugin does nothing |
| `--libmon-no-retval` | skip return hooks: no `ReturnValue`, and calls are reported when made rather than when they return |
| `--userhook-no-addr` | suppress raw pointer values in string arguments |

`no-retval` on an individual line exempts one function, which is worth doing
for anything hot when return values are otherwise enabled.

## Events

`api_called` carries `Library`, `CalledFrom`, `ReturnValue`, `FromModule` and
`Arguments`, alongside the fields every plugin emits — including `Method`,
which is the function name. `hook_placed` reports each breakpoint as it goes
in, and `not_tracked` says why a process was given up on, which is the only
signal available in a release build where `PRINT_DEBUG` is compiled out.

## How it works

Windows library-call monitoring is built on PE export tables and
`NtMapViewOfSection`; neither exists here, so libmon follows glibc's
dynamic-linker rendezvous protocol, the same mechanism gdb uses.

Per process it hooks `finalize_exec`, reads `AT_BASE` from the aux vector in
`mm_struct.saved_auxv` to find ld.so, then waits — retrying on page faults —
until ld.so has initialised `r_debug`. It takes the rendezvous address from
`r_debug.r_brk` and breakpoints it, so every later `dlopen`/`dlclose` is
observed, and walks `link_map` to enumerate what is already loaded. Symbols
are resolved in each library's own `.dynsym` at the load address the linker
reported, and a breakpoint goes on the resolved address.

A library's extent comes from its `PT_LOAD` headers, which is what `FromModule`
is matched against — `link_map` reports where each library starts but not where
it ends. When a library is unloaded its breakpoints come out with it, since a
later `dlopen` may map something else over the same addresses.

Several points are less obvious than they look:

- `load_elf_binary` cannot be hooked. It is static in `fs/binfmt_elf.c` and
  the address a profile gives for it is not where the kernel executes.
- The VMA list cannot be walked. Linux 6.1 replaced `mm_struct.mmap` and
  `vm_area_struct.vm_next` with a maple tree, so anything that looks up a
  library by name silently finds nothing on a newer kernel.
- `_dl_debug_state` cannot be resolved. glibc marks it `rtld_hidden`, so it is
  absent from ld.so's `.dynsym`; `r_brk` is the supported way to find it.
- A breakpoint needs its page resident. At exec nothing is, and a function the
  process has never called never becomes so, which is why hooks are deferred
  and retried rather than failing.
- The breakpoint is in a page shared by every process mapping the library, so
  it fires for processes that were never hooked. Events are filtered by pid.

## Limitations

- glibc and x86-64 only. musl's linker is not handled, and 32-bit `r_debug`
  and `link_map` layouts differ.
- Statically linked binaries are invisible: no interpreter, so no `link_map`
  to observe.
- Hooks land a few milliseconds after `exec`. A process that does its work and
  exits inside that window is missed.
- A hook on a function whose page stays cold may never be placed. Faulting
  those pages in deliberately is possible but currently kills the monitored
  process, since the injection derails DRAKVUF's breakpoint resume.
- When a name has several versions, the default one is chosen via
  `.gnu.version`. Symbols reached only through a relocation are not resolved.
