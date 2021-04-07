#pragma once

#include "ntdll.h"

#include <Windows.h>
#include <Lmcons.h>
#include <strsafe.h>
#include <comdef.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <pathcch.h>

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Pathcch.lib")

#define AUTHOR L"@itm4n"
#define VERSION L"0.4"

extern BOOL g_bVerbose;
extern BOOL g_bDebug;
extern BOOL g_bForce;
extern DWORD g_dwProcessId;
extern LPWSTR g_pwszDumpFilePath;
extern LPWSTR g_pwszProcessName;

BOOL ParseArguments(int argc, wchar_t* argv[]);
VOID PrintArguments();
VOID PrintUsage();

VOID PrintLastError(LPCWSTR pwszFunctionName);
VOID PrintVerbose(LPCWSTR pwszFormat, ...);
VOID PrintDebug(LPCWSTR pwszFormat, ...);

BOOL ProcessGetProtectionLevel(DWORD dwProcessId, PDWORD pdwProtectionLevel);
BOOL ProcessGetProtectionLevelAsString(DWORD dwProcessId, LPWSTR* ppwszProtectionLevel);
BOOL ProcessGetIntegrityLevel(DWORD dwProcessId, PDWORD pdwIntegrityLevel);
BOOL ProcessGetPIDFromName(LPWSTR pwszProcessName, PDWORD pdwProcessId);

HANDLE ObjectManagerCreateDirectory(LPCWSTR dirname);
HANDLE ObjectManagerCreateSymlink(LPCWSTR linkname, LPCWSTR targetname);

BOOL TokenGetSid(HANDLE hToken, PSID* ppSid);
BOOL TokenGetSidAsString(HANDLE hToken, LPWSTR* ppwszStringSid);
BOOL TokenCompareSids(PSID pSidA, PSID pSidB);
BOOL TokenGetUsername(HANDLE hToken, LPWSTR* ppwszUsername);
BOOL TokenCheckPrivilege(HANDLE hToken, LPCWSTR pwszPrivilege, BOOL bEnablePrivilege);
BOOL TokenIsNotRestricted(HANDLE hToken, PBOOL pbIsNotRestricted);

BOOL MiscSystemArchIsAmd64();
BOOL MiscGenerateGuidString(LPWSTR* ppwszGuid);
