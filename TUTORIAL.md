# Delpheed - Step-by-step tutorial

This walks you from building the tools to reading the class list out of packed 32-bit and 64-bit Delphi binaries.

---

## 0. What you need

- **Windows** - the unpacking tools use the Windows debug API.
- **Delphi / RAD Studio** (10.3 Rio or newer via IDE `Delpheed.groupproj` or Pro+ CLI `dcc32`/`dcc64`) **or Free Pascal 3.2.2+** (`fpc` with Win32 + Win64 targets for CLI `build.bat` builds).
- **A throwaway virtual machine with snapshots** if you'll analyse anything you don't fully trust. The unpackers **run the target's own unpacking stub** - treat every packed sample as live code.
- Both **32-bit and 64-bit** targets are supported across the pipeline (`Delpheed` and `Delpheed64` handle both automatically when built together into `bin\`).

> **Rule:** only analyse binaries you are authorised to. Unpack untrusted samples in a VM you can roll back.

---

## 1. Build the tools

Run:

```
build.bat
```

`build.bat` uses `dcc32`/`dcc64` if available and enabled for CLI builds, or Free Pascal (`fpc`) automatically. (Note: RAD Studio Community Edition disables `dcc32`/`dcc64` on the command line - use `Delpheed.groupproj` inside the RAD Studio IDE or Free Pascal via `build.bat`.)

You end up with seven executables in `bin\`:

```
bin\VMTScan.exe      list classes in a PE (32-bit tool; scans PE32 & PE32+)
bin\VMTScan64.exe    list classes in a PE (64-bit tool; scans PE32 & PE32+)
bin\Unpack.exe       unpack a 32-bit PUSHAD-stub packer (ESP trick)
bin\OEPScan.exe      unpack a 32-bit binary via the guard-page OEP finder
bin\OEPScan64.exe    unpack a 64-bit binary via the guard-page OEP finder
bin\Delpheed.exe     one-shot: detect -> unpack -> analyse (32-bit & 64-bit targets)
bin\Delpheed64.exe   64-bit native one-shot: detect -> unpack -> analyse (32-bit & 64-bit targets)
```

---

## 2. Tutorial A - list the classes in a normal Delphi program

Pick any Delphi-built `.exe` or `.dll`/`.bpl` (32-bit or 64-bit):

```
bin\VMTScan.exe C:\path\to\App.exe
```

Read the output top to bottom:

- **PE summary** - bitness, image base, entry point, section count.
- **VMT scan -> Layout** - e.g. `selfptr -88 (Delphi 2009+ (x86))` or `selfptr -176 (Delphi (x64))`.
- **Classes** - one line each: `class: TButton; size=272; parent=TWinControl`.

---

## 3. Tutorial B - detect packing and unpack (32-bit or 64-bit)

Pack a *copy* of a test exe with **UPX**:

```
copy App.exe Packed.exe
upx Packed.exe
```

Run the one-shot analyzer:

```
bin\Delpheed.exe Packed.exe
```

Because it detected packing, `Delpheed` launches the matching bitness unpacker (`TOEPFinder` for 32-bit, or companion `OEPScan64.exe` for 64-bit), dumps the unpacked image to `Packed_unpacked.exe`, rebuilds its imports to `Packed_unpacked_fixed.exe`, and lists the recovered classes.

For manual control:

```
bin\OEPScan.exe   Packed32.exe Packed32_dump.exe /iat
bin\OEPScan64.exe Packed64.exe Packed64_dump.exe /iat
bin\VMTScan.exe   Packed64_dump.exe
```

For 32-bit `PUSHAD` stubs (such as UPX), the ESP-trick unpacker is also available:

```
bin\Unpack.exe Packed32.exe Packed32_dump.exe
```

---

## 4. Tutorial C - a target that detects debuggers

If a protected sample **times out** or **exits before the OEP**, add `/aad`:

```
bin\Delpheed.exe  Protected.exe /aad
bin\OEPScan.exe   Protected32.exe dump32.exe /aad /iat
bin\OEPScan64.exe Protected64.exe dump64.exe /aad /iat
```

`/aad` patches the target's PEB (`BeingDebugged`, `NtGlobalFlag`), clears the heap debug flags, and hooks `NtSetInformationThread` / `NtQueryInformationProcess` in both 32-bit and 64-bit targets.

---

## 5. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `This version of the product does not support command line compiling` | RAD Studio Community Edition blocks `dcc32`/`dcc64` CLI builds. Use `Delpheed.groupproj` in the IDE or Free Pascal via `build.bat`. |
| `Not a 32-bit PE32 image` / `Not a 64-bit PE32+ image` | Use `OEPScan` for 32-bit and `OEPScan64` for 64-bit (or `Delpheed`/`Delpheed64`, which choose automatically). |
| `Timed out` / `exited before OEP` | Anti-debug (add `/aad`); or the stub re-granted execute via `VirtualProtect` before jumping to OEP (for 32-bit `PUSHAD`, use `Unpack.exe`). |
| `No IAT found` | Try without `/iat`, or the sample resolves imports lazily at runtime. |
| `CreateProcess failed` | Ensure `OEPScan.exe` and `OEPScan64.exe` are built side-by-side in `bin\`. |
