#include "exploit.h"

#include <iostream>

BOOL g_bVerbose = FALSE;
BOOL g_bDebug = FALSE;
BOOL g_bForce = FALSE;
DWORD g_dwProcessId = 0;
LPWSTR g_pwszDumpFilePath = NULL;
LPWSTR g_pwszProcessName = NULL;

int wmain(int argc, wchar_t* argv[])
{
    if (!ParseArguments(argc, argv))
        return 1;

    //PrintArguments();

    if (g_pwszProcessName != NULL)
    {
        DumpProcessByName(g_pwszProcessName, g_pwszDumpFilePath);
    }
    else if (g_dwProcessId != 0)
    {
        DumpProcess(g_dwProcessId, g_pwszDumpFilePath);
    }

    return 0;
}
