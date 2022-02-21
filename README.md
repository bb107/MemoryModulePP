# MemoryModulePP

MemoryModulePP, used to load a DLL from memory. MemoryModulePP is compatible with Win32 API and supports exception handling.

**MemoryModulePP is developed based on [MemoryModule][ref1].**

> In order to support 32-bit dll exception handling, the dll should enable the /SAFESEH linker option, 
> otherwise the exception handler cannot pass the RtlIsValidHandler () check when an exception occurs

## Features
  - Compatible with Win32 API (GetModuleHandle, GetModuleFileName, GetProcAddress and any Resource API)
  - Support for C++ exceptions and SEH
  - Optimized MEMORYMODULE structure
  - Use reference counting, repeated loading of the same module will update the reference counting, please refer to LdrLoadDllMemoryExW
  - The above features can be turned off through the dwFlags parameter of LdrLoadDllMemoryExW
  - Support for TLS(Thread Local Storage)
  - DllMain can receive four types of notifications
  - Support forward export
  - Provides limited support for .net assembly loading

## Tech

MemoryModulePP uses many open source projects and references to work properly:

* [Vergilius Project][ref0] - Some windows kernel structure reference.
* [MemoryModule][ref1] - Load dll from memory, reference and improve part of this repository's code.
* [Blackbone][ref2] - Windows memory hacking library, Referenced the idea of exception handling.
* [Exceptions on Windows x64][ref3] - How Windows x64 Exception Handling Works. (Russian)
* [Reactos][ref4] - How Windows loads dll.

## Todos
 - Looking for a good way to locate the LdrpHandleTlsData function, or implement this function.



   [ref0]: <https://www.vergiliusproject.com>
   [ref1]: <https://github.com/fancycode/MemoryModule.git>
   [ref2]: <https://github.com/DarthTon/Blackbone.git>
   [ref3]: <https://habr.com/en/company/aladdinrd/blog/321868/>
   [ref4]: <https://doxygen.reactos.org/>
   [ref5]: <https://github.com/processhacker/processhacker.git>
   
