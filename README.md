# MemoryModulePP

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

MemoryModulePP, used to load a DLL from memory. MemoryModulePP is compatible with Win32 API and supports exception handling.

**MemoryModulePP is developed based on [MemoryModule][ref1].**

**This repository is under development.**

## New Features
  - Support Win10 forward export

## Features
  - Compatible with Win32 API (GetModuleHandleA/W/Ex GetModuleFileNameA/W/Ex GetProcAddress and any Resource API)
  - Support for C++ exceptions and SEH
  - Compatible with Win7 and Win10
  - Optimized MEMORYMODULE structure
  - Use reference counting, repeated loading of the same module will update the reference counting, please refer to NtLoadDllMemoryExW
  - The above features can be turned off through the dwFlags parameter of NtLoadDllMemoryExW
  - Support for TLS(Thread Local Storage)
  - DllMain can receive four types of notifications

## Tech

MemoryModulePP uses many open source projects and references to work properly:

* [Vergilius Project][ref0] - Some windows kernel structure reference.
* [MemoryModule][ref1] - Load dll from memory, reference and improve part of this repository's code.
* [Blackbone][ref2] - Windows memory hacking library, Referenced the idea of exception handling.
* [Exceptions on Windows x64][ref3] - How Windows x64 Exception Handling Works. (Russian)
* [Reactos][ref4] - How WIndows loads dll.

## Todos

 - Compatible with Win8 and x86 architecture
 - Improve MEMORYPODULE structure
 - Improve NtLoadDllMemoryExW function


   [ref0]: <https://www.vergiliusproject.com>
   [ref1]: <https://github.com/fancycode/MemoryModule.git>
   [ref2]: <https://github.com/DarthTon/Blackbone.git>
   [ref3]: <https://habr.com/en/company/aladdinrd/blog/321868/>
   [ref4]: <https://doxygen.reactos.org/>
   
