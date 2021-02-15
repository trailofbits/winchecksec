winchecksec
===========

[![Build Status](https://img.shields.io/github/workflow/status/trailofbits/winchecksec/CI/master)](https://github.com/trailofbits/winchecksec/actions?query=workflow%3ACI)

`winchecksec` performs static detection of common Windows security features.

The following security features are currently detected:

* ASLR:
    * `/DYNAMICBASE` with stripped relocation entries edge-case
    * `/HIGHENTROPYVA` for 64-bit systems
* Code integrity/signing:
    * `/INTEGRITYCHECK`
    * Authenticode-signed with a valid (trusted, active) certificate (currently unsupported on Linux)
* DEP (a.k.a. W^X, NX)
* Manifest isolation via (`/ALLOWISOLATION`)
* Structured Exception Handling and SafeSEH support
* Control Flow Guard and Return Flow Guard instrumentation
* Stack cookie (`/GS`) support

## Building

`winchecksec` depends on [pe-parse](https://github.com/trailofbits/pe-parse) and
[uthenticode](https://github.com/trailofbits/uthenticode), which can be installed via `vcpkg`:

```bash
$ vcpkg install pe-parse uthenticode
```

**NOTE**: On Windows, `vcpkg` defaults to 32-bit builds. If you're doing a 64-bit `winchecksec`
build, you'll need to explicitly build the dependencies as 64-bit:

```bash
$ vcpkg install pe-parse:x64-windows uthenticode:x64-windows
```

### Building on Linux
```bash
$ git clone https://github.com/trailofbits/winchecksec.git
$ cd winchecksec
$ mkdir build
$ cd build
$ cmake -DCMAKE_BUILD_TYPE=Release ..
$ cmake --build .
$ ./build/winchecksec
```

### Building on Windows
```cmd
> git clone https://github.com/trailofbits/winchecksec.git
> cd winchecksec
> mkdir build
> cd build
> cmake ..
> cmake --build . --config Release
> .\Release\winchecksec.exe C:\Windows\notepad.exe
```

## Usage

As a command-line tool, `winchecksec` has two output modes: a plain-text mode for easy reading,
and a JSON mode for consumption in other programs. The plain-text mode is the default; JSON output
is enabled by passing `--json` or `-j`:

```cmd
> .\Release\winchecksec.exe C:\Windows\notepad.exe

Dynamic Base    : "Present"
ASLR            : "Present"
High Entropy VA : "Present"
Force Integrity : "NotPresent"
Isolation       : "Present"
NX              : "Present"
SEH             : "Present"
CFG             : "NotPresent"
RFG             : "NotPresent"
SafeSEH         : "NotApplicable"
GS              : "Present"
Authenticode    : "NotPresent"
.NET            : "NotPresent"

> .\Release\winchecksec.exe -j C:\Windows\notepad.exe

[{
   "path": "C:\\Windows\\notepad.exe",
   "mitigations": {
      "dynamicBase": {
         "presence": "Present",
         "description": "Binaries with dynamic base support can be dynamically rebased, enabling ASLR."
      },
      "rfg": {
         "description": "Binaries with RFG enabled have additional return-oriented-programming protections.",
         "presence": "NotPresent"
      },
      "seh": {
         "description": "Binaries with SEH support can use structured exception handlers.",
         "presence": "Present"
      },
      // ...
   }
}]
```

`winchecksec` also provides a C++ API; documentation is hosted
[here](https://trailofbits.github.io/winchecksec/).

## Hacking

`winchecksec` is formatted with `clang-format`. You can use the `clang-format` target to
auto-format it locally:

```bash
$ make clang-format
```

`winchecksec` also comes with a suite of unit tests that use
[pegoat](https://github.com/trailofbits/pegoat) as a reference for various security mitigations.
To build the unit tests, pass `-DBUILD_TESTS=1` to the CMake build.

## Statistics for different flags across EXEs on Windows 10

Prevalence of various security features on a vanilla Windows 10 (1803) installation:

| aslr | authenticode | cfg | dynamicBase | forceIntegrity | gs | highEntropyVA |  isolation |  nx |  rfg | safeSEH |  seh |
| ---- | ------------ | --- | ----------- | -------------- | -- | ------------- | ---------- | --- | ---  | ------- | --- |
| 79%	| 37% | 49%	| 79% | 3% | 65% | 43% | 100% | 79% | 6% | 25%| 91% |
