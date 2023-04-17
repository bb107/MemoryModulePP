# MemoryModulePP

MemoryModulePP, used to load a DLL from memory. MemoryModulePP is compatible with Win32 API and supports exception handling.

**MemoryModulePP is developed based on [MemoryModule][ref1].**

## Features
  - Compatible with Win32 API (GetModuleHandle, GetModuleFileName, GetProcAddress and any Resource API)
  - Support for C++ exceptions and SEH
    > In order to support 32-bit dll exception handling, the dll should enable the /SAFESEH linker option, 
    > otherwise the exception handler cannot pass the ```RtlIsValidHandler()``` check when an exception occurs
  - Support reference counting
  - Support Thread Local Storage<br/>
    *There are 2 ways to handle tls: MmpTls and LdrpTls, which you can control via ```MMPP_USE_TLS``` macro in stdafx.h.*<br/><br/>
    <table>
        <tr>
            <th/>
            <th>MmpTls(MmpTls.cpp)</th>
            <th>LdrpTls(MmpLdrpTls.cpp)</th>
        </tr>
        <tr>
            <th>Description</th>
            <td>Implemented by MemoryModulePP</td>
            <td>Implemented by NTDLL</td>
        </tr>
        <tr>
            <th>Compatibility</th>
            <td>Medium</td>
            <td>Low</td>
        </tr>
        <tr>
            <th>Stability</th>
            <td>Low</td>
            <td>High</td>
        </tr>
    </table>
  - DllMain can receive four types of notifications
  - Support forward export
  - Support ```SetUnhandledExceptionFilter()```
  - Provides limited support for .NET assembly loading

## Tech

MemoryModulePP uses many open source projects and references to work properly:

* [Vergilius Project][ref0] - Some windows kernel structure reference.
* [MemoryModule][ref1] - Load dll from memory, reference and improve part of this repository's code.
* [Blackbone][ref2] - Windows memory hacking library, Referenced the idea of exception handling.
* [Exceptions on Windows x64][ref3] - How Windows x64 Exception Handling Works. (Russian)
* [Reactos][ref4] - How Windows loads dll.

## Todos
 - Add support for ReflectionLoader
 - Improve the stability of MmpTls
 - Bug fixes

[ref0]: <https://www.vergiliusproject.com>
[ref1]: <https://github.com/fancycode/MemoryModule.git>
[ref2]: <https://github.com/DarthTon/Blackbone.git>
[ref3]: <https://habr.com/en/company/aladdinrd/blog/321868/>
[ref4]: <https://doxygen.reactos.org/>
[ref5]: <https://github.com/processhacker/processhacker.git>
