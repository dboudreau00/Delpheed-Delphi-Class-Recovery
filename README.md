<img width="1024" height="692" alt="9105b90f-e021-458f-b723-79b90ddadafa" src="https://github.com/user-attachments/assets/6629a254-c929-4cd0-a7a5-c87bfce4c38c" />

# Delpheed

A small reverse-engineering toolkit for **Delphi PE executables** (both **32-bit** and **64-bit**), written in Object Pascal / Delphi.
It parses the binary, recovers the class model from Delphi's runtime metadata, and - for packed samples - unpacks them via a debugger so the real class information becomes readable. Think of it as a focused, Delphi-aware slice of what IDA + Scylla do.

<img width="1024" height="692" alt="59fcfaa6-c8de-47e9-9611-5b703894063a" src="https://github.com/user-attachments/assets/13f4088c-ea5e-4ca2-8f20-c06194c62e88" />

**New here?** See **`TUTORIAL.md`** for a hands-on, step-by-step walkthrough.

## What it does

- **Recover the class hierarchy** of a Delphi binary (PE32 and PE32+) - every class name, instance size, and parent - by locating VMTs through their self-pointer and validating them against Delphi's fixed VMT field layout (no disassembly required).
- **Detect packing** statically - per-section Shannon entropy, entry-point placement, import-table size, and known packer section-name signatures.
- **Unpack** common compressors two ways: the **ESP trick** (for 32-bit `PUSHAD` stubs) and a **guard-page / NX OEP finder** (for 32-bit and 64-bit stubs, including non-`PUSHAD` stubs).
- **Rebuild the import table** of a 32-bit or 64-bit dump so it loads again (Scylla-style).
- **Hide the debugger** from protectors that check for it (x86/x64 PEB/heap patching + `ntdll` inline hooks).

## Pipeline

```
  target.exe (32-bit or 64-bit)
      |
      v
  [uPEFile]          parse PE32/PE32+ headers, RVA<->offset<->VA, safe reads
      |
      v
  [uPackDetect]      packed?  -- no --> ---------------------------.
      |                                                            |
     yes                                                           |
      v                                                            |
  [uOEPFinder / uOEPFinder64]   run under bitness-matched debugger:|
    [uAntiAntiDebug / 64]         hide the debugger (optional)     |
    strip execute from non-stub sections, catch OEP fault          |
    dump the unpacked image                                        |
    [uIATRebuild / 64]            reconstruct imports -> *_fixed.exe
      |                                                            |
      v                                                            v
  [uDelphiVMT]       recover classes  <--------------------- (scan directly)
      |
      v
  class list (name, size, parent)
```

`Delpheed` / `Delpheed64` wire these together automatically for **both** 32-bit and 64-bit targets (delegating cross-bitness unpacking to companion `OEPScan64.exe` / `OEPScan.exe`). `uUnpacker` is the alternative ESP-trick unpacker for 32-bit `PUSHAD` stubs.

## Files

| File | Role |
|------|------|
| `uPEFile.pas` | PE32/PE32+ parser: headers, sections, address translation, bounds-checked reads |
| `uDelphiVMT.pas` | VMT scanner: recovers classes + hierarchy from self-pointers and VMT layout |
| `uPackDetect.pas` | Packer detection: entropy, entry point, imports, known packer names |
| `uUnpacker.pas` | ESP-trick unpacker for 32-bit `PUSHAD` stubs (Debug API + hardware breakpoint) |
| `uOEPFinder.pas` | 32-bit guard-page OEP finder; integrates anti-anti-debug + import rebuild |
| `uIATRebuild.pas` | 32-bit import-table reconstruction from the resolved IAT and live module exports |
| `uAntiAntiDebug.pas` | 32-bit PEB/heap patching + `ntdll` inline hooks to hide the debugger |
| `uOEPFinder64.pas` | 64-bit guard-page OEP finder (PE32+, x64 `CONTEXT`) |
| `uIATRebuild64.pas` | 64-bit import reconstruction (PE32+, 8-byte thunks) |
| `uAntiAntiDebug64.pas` | 64-bit anti-anti-debug (x64 PEB offsets, x64 `ntdll` hooks) |
| `uConsoleOut.pas` | Accessible console output (labelled text, word-based status, exit codes) |
| `uVMTScanMain.pas` | Shared driver logic for `VMTScan` / `VMTScan64` |
| `uDelpheedMain.pas` | Shared one-shot driver logic for `Delpheed` / `Delpheed64` |
| `VMTScan.dpr` / `VMTScan64.dpr` | Driver: list classes in a PE (32-bit / 64-bit builds, read both PE32 & PE32+) |
| `Unpack.dpr` | Driver: ESP-trick unpack (32-bit) |
| `OEPScan.dpr` | Driver: guard-page unpack, 32-bit (`/aad`, `/iat`) |
| `OEPScan64.dpr` | Driver: guard-page unpack, 64-bit (`/aad`, `/iat`) |
| `Delpheed.dpr` / `Delpheed64.dpr` | Driver: one-shot detect -> unpack -> analyse (32-bit & 64-bit builds, handle both PE32 & PE32+) |
| `Delpheed.groupproj` / `*.dproj` | RAD Studio project group and projects for IDE builds (Win32 + Win64) |
| `build.bat` | Build all 32-bit and 64-bit tools into `bin\` (`dcc32`/`dcc64` or Free Pascal `fpc`) |

## Build

All tools compile cleanly in both **Delphi / RAD Studio** and **Free Pascal 3.2.2+** (`-Mdelphi`):

```
build.bat             rem builds 32-bit (VMTScan, Unpack, OEPScan, Delpheed)
                      rem and 64-bit (VMTScan64, OEPScan64, Delpheed64) into bin\
```

- If you have RAD Studio Pro/Enterprise/Architect, run `rsvars.bat` then `build.bat` (`dcc32`/`dcc64`).
- If you have **RAD Studio Community Edition** (which disables `dcc32`/`dcc64` CLI compiling), either open `Delpheed.groupproj` in the RAD Studio IDE and choose **Project -> Build All**, or run `build.bat` with Free Pascal (`fpc`) installed.

## Usage

```
VMTScan       <target.exe|dll>
VMTScan64     <target.exe|dll>
Unpack        <packed.exe> [output.exe]
OEPScan       <packed.exe> [dump.exe] [/aad] [/iat]    (32-bit target)
OEPScan64     <packed.exe> [dump.exe] [/aad] [/iat]    (64-bit target)
Delpheed      <target.exe> [/aad]                      (32-bit or 64-bit target)
Delpheed64    <target.exe> [/aad]                      (32-bit or 64-bit target)
```

Typical one-shot run (works for both 32-bit and 64-bit targets):

```
bin\Delpheed.exe suspicious.exe /aad
```

which detects packing, unpacks using the matching 32-bit or 64-bit unpacker (hiding the debugger and rebuilding imports to `suspicious_unpacked_fixed.exe`), and lists the recovered classes.

Manual, step by step:

```
bin\OEPScan.exe   packed32.exe packed32_dump.exe /aad /iat
bin\OEPScan64.exe packed64.exe packed64_dump.exe /aad /iat
bin\VMTScan.exe   packed64_dump.exe
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | bad or missing arguments |
| 2 | input could not be read / not a valid PE |
| 3 | ran, but the operation failed |

## Accessibility

This is a command-line project, so "accessible" here means terminal/screen-reader friendly, via `uConsoleOut`:

- status is carried by **words** (`OK:`, `ERROR:`, `WARNING:`, `INFO:`), never colour;
- output is **linear and labelled** (`Name: value`), not aligned columns or tables;
- no box-drawing, spinners, or cursor tricks;
- **errors and warnings go to stderr**, normal output to stdout;
- a quiet mode drops decorative output but keeps the result line;
- every tool returns a **meaningful exit code**.

## Scope and limits

- **Both bitnesses are supported.** `VMTScan` / `VMTScan64` and `Delpheed` / `Delpheed64` handle both PE32 and PE32+. Dynamic unpacking uses `OEPScan` / `Unpack` (32-bit) and `OEPScan64` (64-bit); `Delpheed` and `Delpheed64` automatically route cross-bitness packed samples to the matching companion unpacker in `bin\`.
- **Plain compressors** (UPX, ASPack, MPRESS, older PECompact) unpack well. Strong protectors (Themida, VMProtect, Enigma) use anti-debug and virtualization that these methods do not defeat.
- The **guard-page finder needs DEP** enforced (the default for 32-bit and 64-bit processes on 64-bit Windows).
- **Import reconstruction is heuristic** (longest run of module-pointers outside the stub section) and flags any unresolved thunks rather than guessing them.
- Dumps assume the target sits at its preferred/actual image base; a stub that calls `VirtualProtect` to re-grant execute before jumping to OEP or unpacks outside the image can defeat the guard-page finder (for 32-bit `PUSHAD` stubs, `Delpheed` falls back to the ESP trick automatically).
