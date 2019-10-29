winchecksec
===========

[![Build Status](https://travis-ci.com/trailofbits/winchecksec.svg?branch=master)](https://travis-ci.com/trailofbits/winchecksec)

`winchecksec` performs static detection of common Windows security features.

The following security features are currently detected:

* ASLR:
    * `/DYNAMICBASE` with stripped relocation entries edge-case
    * `/HIGHENTROPYVA` for 64-bit systems
* Code integrity/signing:
    * `/INTEGRITYCHECK`
    * Authenticode-signed with a valid (trusted, active) certificate
* DEP (a.k.a. W^X, NX)
* Manifest isolation via (`/ALLOWISOLATION`)
* Structured Exception Handling and SafeSEH support
* Control Flow Guard and Return Flow Guard instrumentation
* Stack cookie (`/GS`) support

## Building

`winchecksec` has no dependencies other than Windows itself, and should build
with any reasonably modern `cmake`. It'll audit binaries of any architecture,
but you should build it as 64-bit:

```cmd
> mkdir build
> cd build
> cmake -G "Visual Studio 15 2017 Win64" ..
> cmake --build . --config Release
> .\Release\winchecksec.exe C:\Windows\notepad.exe
```

## Usage

`winchecksec` has two output modes: a plain-text mode for easy reading, and a JSON mode
for consumption in other programs. The plain-text mode is the default; JSON output is
enabled by passing `-j`:

```cmd
> .\Release\winchecksec.exe C:\Windows\notepad.exe

Dynamic Base    : true
ASLR            : true
High Entropy VA : true
Force Integrity : false
Isolation       : true
NX              : true
SEH             : true
CFG             : true
RFG             : false
SafeSEH         : false
GS              : true
Authenticode    : false

> .\Release\winchecksec.exe -j C:\Windows\notepad.exe

{"aslr":true,"authenticode":false,"cfg":true,"dynamicBase":true,"forceIntegrity":false,"gs":true,"highEntropyVA":true,"isolation":true,"nx":true,"path":"C:\\Windows\\notepad.exe","rfg":false,"safeSEH":false,"seh":true}
```

`winchecksec` only takes one file at a time. To run it on multiple files or entire directories,
wrap it in a loop.

## Statistics for different flags across EXEs on Windows 10

Prevalence of various security features on a vanilla Windows 10 (1803) installation:

| aslr | authenticode | cfg | dynamicBase | forceIntegrity | gs | highEntropyVA |  isolation |  nx |  rfg | safeSEH |  seh |
| ---- | ------------ | --- | ----------- | -------------- | -- | ------------- | ---------- | --- | ---  | ------- | --- |
| 79%	| 37% | 49%	| 79% | 3% | 65% | 43% | 100% | 79% | 6% | 25%| 91% |
