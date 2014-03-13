/*
 * This file is part of SzimatSzatyor.
 *
 * SzimatSzatyor is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * SzimatSzatyor is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with SzimatSzatyor.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "HookEntryManager.h"
#include <psapi.h>
#include <Shlwapi.h>
#include <cstdio>
#include <io.h>

/* static */
WORD HookEntryManager::GetBuildNumberFromProcess(HANDLE hProcess /* = NULL */)
{
    // will contain where the process is which will be injected
    char processExePath[MAX_PATH];

    // size of the path
    DWORD processExePathSize = 0;
    // gets the path of the current process' executable
    // param process should be NULL in the sniffer
    if (!hProcess)
        processExePathSize = GetModuleFileName(NULL, processExePath, MAX_PATH);
    // gets the path of an external process' executable
    // param process should NOT be NULL in the injector
    else
        processExePathSize = GetModuleFileNameEx(hProcess, NULL, processExePath, MAX_PATH);
    if (!processExePathSize)
    {
        printf("ERROR: Can't get path of the process' exe, ErrorCode: %u\n", GetLastError());
        return 0;
    }
    printf("ExePath: %s\n", processExePath);

    // size of the file version info
    DWORD fileVersionInfoSize = GetFileVersionInfoSize(processExePath, NULL);
    if (!fileVersionInfoSize)
    {
        printf("ERROR: Can't get size of the file version info,");
        printf("ErrorCode: %u\n", GetLastError());
        return 0;
    }

    // allocates memory for file version info
    BYTE* fileVersionInfoBuffer = new BYTE[fileVersionInfoSize];
    // gets the file version info
    if (!GetFileVersionInfo(processExePath, 0, fileVersionInfoSize, fileVersionInfoBuffer))
    {
        printf("ERROR: Can't get file version info, ErrorCode: %u\n", GetLastError());
        delete [] fileVersionInfoBuffer;
        return 0;
    }

    // structure of file version info
    // actually this pointer will be pointed to a part of fileVersionInfoBuffer
    VS_FIXEDFILEINFO* fileInfo = NULL;
    // gets the needed info (root) from the file version info resource
    // \ means the root block (VS_FIXEDFILEINFO)
    // note: escaping needed so that's why \\ used
    if (!VerQueryValue(fileVersionInfoBuffer, "\\", (LPVOID*)&fileInfo, NULL))
    {
        printf("ERROR: File version info query is failed.\n");
        delete [] fileVersionInfoBuffer;
        return 0;
    }

    // last (low) 2 bytes
    WORD buildNumber = fileInfo->dwFileVersionLS & 0xFFFF;
    delete [] fileVersionInfoBuffer;
    return buildNumber;
}

bool HookEntryManager::GetOffsets(const HINSTANCE moduleHandle, const WORD build, HookEntry* entry)
{
    char ret[20];
    char fileName[MAX_PATH];
    char dllPath[MAX_PATH];
    char section[6];

    GetModuleFileName((HMODULE)moduleHandle, dllPath, MAX_PATH);
    // removes the DLL name from the path
    PathRemoveFileSpec(dllPath);

    _snprintf(fileName, MAX_PATH, "%s\\offsets.ini", dllPath);
    _snprintf(section, 6, "%i", build);

    if (access(fileName, 0) != -1)
    {
        printf("ERROR: File \"%s\" does not exist.\n", fileName);
        printf("\noffsets.ini template:\n");
        printf("[build]\n");
        printf("send = 0xDEADBEEF\n");
        printf("recive=0xDEADBEEF\n");
        printf("locale=0xDEADBEEF\n\n");
        return false;
    }

    GetPrivateProfileString(section, "send", "0", ret, 20, fileName);
    entry->send = strtol(ret, 0, 0);

    GetPrivateProfileString(section, "recive", "0", ret, 20, fileName);
    entry->recive = strtol(ret, 0, 0);

    // optional
    GetPrivateProfileString(section, "locale", "0", ret, 20, fileName);
    entry->locale = strtol(ret, 0, 0);

    return entry->recive != 0 && entry->send != 0;
}
