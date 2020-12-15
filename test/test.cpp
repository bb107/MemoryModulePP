#include "../MemoryModule/LoadDllMemoryApi.h"
#include <cstdio>
#pragma warning(disable:4996)

static PVOID ReadDllFile(LPCSTR FileName) {
    LPVOID buffer;
    size_t size;
    FILE* f = fopen(FileName, "rb");
    if (!f)return 0;
    _fseeki64(f, 0, SEEK_END);
    if (!(size = _ftelli64(f))) {
        fclose(f);
        return 0;
    }
    _fseeki64(f, 0, SEEK_SET);
    fread(buffer = new char[size], 1, size, f);
    fclose(f);
    return buffer;
}

int test_default() {
    LPVOID buffer = ReadDllFile("a.dll");
    
    HMEMORYMODULE m1 = nullptr, m2 = m1;
    HMODULE hModule = nullptr;
    FARPROC pfn = nullptr;
    DWORD MemoryModuleFeatures = 0;

    typedef int(* _exception)(int code);
    _exception exception = nullptr;
    HRSRC hRsrc;
    DWORD SizeofRes;
    HGLOBAL gRes;
    char str[10];

    LdrQuerySystemMemoryModuleFeatures(&MemoryModuleFeatures);
    if (MemoryModuleFeatures != MEMORY_FEATURE_ALL) {
        printf("not support all features on this version of windows.\n");
    }
    
    if (!NT_SUCCESS(LdrLoadDllMemoryExW(&m1, nullptr, 0, buffer, 0, L"kernel64", nullptr))) goto end;
    LoadLibraryW(L"wininet.dll");
    if (!NT_SUCCESS(LdrLoadDllMemoryExW(&m2, nullptr, 0, buffer, 0, L"kernel128", nullptr))) goto end;

    //forward export
    hModule = (HMODULE)m1;
    pfn = (decltype(pfn))(GetProcAddress(hModule, "Socket")); //ws2_32.WSASocketW
    pfn = (decltype(pfn))(GetProcAddress(hModule, "VerifyTruse")); //wintrust.WinVerifyTrust
    hModule = (HMODULE)m2;
    pfn = (decltype(pfn))(GetProcAddress(hModule, "Socket"));
    pfn = (decltype(pfn))(GetProcAddress(hModule, "VerifyTruse"));

    //exception
    hModule = (HMODULE)m1;
    exception = (_exception)GetProcAddress(hModule, "exception");
    if (exception) {
        for (int i = 0; i < 4; ++i)exception(i);
    }
    
    //tls
    pfn = GetProcAddress(hModule, "thread");
    if (pfn && pfn()) {
        printf("thread test failed.\n");
    }

    //resource
    if (!LoadStringA(hModule, 101, str, 10)) {
        printf("load string failed.\n");
    }
    else {
        printf("%s\n", str);
    }
    if (!(hRsrc = FindResourceA(hModule, MAKEINTRESOURCEA(102), "BINARY"))) {
        printf("find binary resource failed.\n");
    }
    else {
        if ((SizeofRes = SizeofResource(hModule, hRsrc)) != 0x10) {
            printf("invalid res size.\n");
        }
        else {
            if (!(gRes = LoadResource(hModule, hRsrc))) {
                printf("load res failed.\n");
            }
            else {
                if (!LockResource(gRes))printf("lock res failed.\n");
                else {
                    printf("resource test success.\n");
                }
            }
        }
    }

end:
    delete[]buffer;
    if (m1)LdrUnloadDllMemory(m1);
    FreeLibrary(LoadLibraryW(L"wininet.dll"));
    FreeLibrary(GetModuleHandleW(L"wininet.dll"));
    if (m2)LdrUnloadDllMemory(m2);

    return 0;
}

#define WSADESCRIPTION_LEN      256
#define WSASYS_STATUS_LEN       128
typedef USHORT ADDRESS_FAMILY;
typedef int (PASCAL* WSAStartup_t)(WORD wVersionRequired, LPWSADATA lpWSAData);
typedef int (PASCAL* WSACleanup_t)(void);
typedef SOCKET (PASCAL* socket_t)(int af, int type, int protocol);
typedef int (PASCAL* closesocket_t)(SOCKET s);
typedef int (PASCAL* connect_t)(SOCKET s, const struct sockaddr FAR* name, int namelen);
typedef unsigned long (PASCAL* inet_addr_t)(const char FAR* cp);
typedef u_short (PASCAL* htons_t)(u_short hostshort);

int test_ws2_32() {
    PVOID buffer = ReadDllFile("C:\\Windows\\system32\\ws2_32.dll");

    HMEMORYMODULE hMemoryModule = nullptr;
    HMODULE hModule = nullptr;
    NTSTATUS status;

    WSAData data{};
    SOCKET sock = INVALID_SOCKET;
    sockaddr_in addr{};
    WSAStartup_t _WSAStartup = nullptr;
    WSACleanup_t _WSACleanup = nullptr;
    socket_t _socket = nullptr;
    closesocket_t _closesocket = nullptr;
    connect_t _connect = nullptr;
    inet_addr_t _inet_addr = nullptr;
    htons_t _htons = nullptr;

    hMemoryModule = LoadLibraryMemoryExW(buffer, 0, L"ws2.dll", nullptr, LOAD_FLAGS_NOT_FAIL_IF_HANDLE_TLS);
    hModule = MemoryModuleToModule(hMemoryModule);
    if (buffer)delete[]buffer;
    if (!hModule)return 0;

    _WSAStartup = (decltype(_WSAStartup)(GetProcAddress(hModule, "WSAStartup")));
    _WSACleanup = (decltype(_WSACleanup)(GetProcAddress(hModule, "WSACleanup")));
    _socket = (decltype(_socket)(GetProcAddress(hModule, "socket")));
    _closesocket = (decltype(_closesocket)(GetProcAddress(hModule, "closesocket")));
    _connect = (decltype(_connect)(GetProcAddress(hModule, "connect")));
    _inet_addr = (decltype(_inet_addr)(GetProcAddress(hModule, "inet_addr")));
    _htons = (decltype(_htons)(GetProcAddress(hModule, "htons")));
    if (!_WSAStartup || !_WSACleanup || !_socket || !_closesocket || !_connect || !_inet_addr || !_htons)goto end;

    if (_WSAStartup(MAKEWORD(2, 2), &data) != 0)goto end;
    if ((sock = _socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)goto end;
    addr.sin_family = AF_INET;
    addr.sin_port = _htons(80);
    addr.sin_addr.S_un.S_addr = _inet_addr("1.1.1.1");
    if (_connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)goto end;

    //success
    printf("ws2_32 completed successfully.\n");

end:
    if (sock != INVALID_SOCKET && _closesocket)_closesocket(sock);
    if (_WSACleanup)_WSACleanup();
    FreeLibraryMemory(hMemoryModule);
    return 0;
}

DWORD WINAPI thread(PVOID) {
    return 0;
}

int main() {
    //test_default();
    //test_ws2_32();
    DWORD dwFeatures = 0;
    LdrQuerySystemMemoryModuleFeatures(&dwFeatures);
    if ((dwFeatures & MEMORY_FEATURE_ALL) != MEMORY_FEATURE_ALL) {
        printf("\n");
        DebugBreak();
    }

    auto a = ReadDllFile("a.dll");

    //LOAD_FLAGS_NOT_HANDLE_TLS
    HMEMORYMODULE p1 = LoadLibraryMemoryExA(a, 0, "a.dll", nullptr, 0),
        p2 = LoadLibraryMemoryExA(a, 0, "b.dll", nullptr, 0);
    delete[]a;

    FreeLibraryMemory(p2);

    HANDLE hThread = CreateThread(nullptr, 0, thread, nullptr, 0, nullptr);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    FreeLibraryMemory(p1);

    return 0;
}
