#pragma once

typedef HRESULT(WINAPI* GetFileVersion_T)(
    LPCWSTR szFilename,
    LPWSTR szBuffer,
    DWORD cchBuffer,
    DWORD* dwLength
    );

BOOL WINAPI MmpPreInitializeHooksForDotNet();
BOOL WINAPI MmpInitializeHooksForDotNet();