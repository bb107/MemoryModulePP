#pragma once

#pragma warning (disable:4005)
#ifndef WIN32_NO_STATUS
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#endif
#pragma warning (default:4005)

//memory module base support
#include "MemoryModule.h"

//nt layer support
#include "Native.h"

//memory block pattern search support
#include "rtlsearch.h"

//windows nt version support
#include "rtlver.h"

//LDR_DATA_TABLE_ENTRY
#include "rtlldr.h"

//rtl inverted function table for exception handling
#include "rtlinv.h"

//tls support
#include "rtltls.h"

//MemoryModulePP api interface
#include "NativeFunctionsInternal.h"

