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
#include "szimat.h"

// entry point of the DLL
BOOL APIENTRY DllMain(HINSTANCE instDLL, DWORD reason, LPVOID /* reserved */)
{
    // called when the DLL is being loaded into the
    // virtual address space of the current process (where to be injected)
    if (reason == DLL_PROCESS_ATTACH)
    {
        instanceDLL = instDLL;
        // disables thread notifications (DLL_THREAD_ATTACH, DLL_THREAD_DETACH)
        DisableThreadLibraryCalls(instDLL);

        // creates a thread to execute within the
        // virtual address space of the calling process (WoW)
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&MainThreadControl, NULL, 0, NULL);
    }
    // the DLL is being unloaded
    else if (reason == DLL_PROCESS_DETACH)
    {
        // close the dump file
        if (fileDump)
            fclose(fileDump);

        // deallocates the console
        ConsoleManager::Destroy();
    }
    return TRUE;
}

DWORD MainThreadControl(LPVOID /* param */)
{
    // creates the console
    if (!ConsoleManager::Create(&isSigIntOccured))
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);

    // some info
    printf("Welcome to SzimatSzatyor, a WoW injector sniffer.\n");
    printf("SzimatSzatyor is distributed under the GNU GPLv3 license.\n");
    printf("Source code is available at: ");
    printf("http://github.com/Konctantin/SzimatSzatyor\n\n");

    printf("Press CTRL-C (CTRL then c) to stop sniffing ");
    printf("(and exit from the sniffer).\n");
    printf("Note: you can simply re-attach the sniffer without ");
    printf("restarting the WoW.\n\n");

    // gets the build number
    buildNumber = GetBuildNumberFromProcess();
    // error occured
    if (!buildNumber)
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("Detected build number: %hu\n", buildNumber);

    // checks this build is supported or not
    if (!GetOffsets(instanceDLL, buildNumber, &hookEntry))
    {
        printf("ERROR: This build number is not supported.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // get the base address of the current process
    DWORD baseAddress = (DWORD)GetModuleHandle(NULL);

    DWORD localeAddress = hookEntry.lang;
    // locale stored in reversed string (enGB as BGne...)
    if (localeAddress)
    {
        for (int i = 3; i >= 0; --i)
            locale[i] = *(char*)(baseAddress + localeAddress++);
        printf("Detected client locale: %s\n", locale);
    }

    // gets where is the DLL which injected into the client
    DWORD dllPathSize = GetModuleFileName((HMODULE)instanceDLL, dllPath, MAX_PATH);
    if (!dllPathSize)
    {
        printf("\nERROR: Can't get the injected DLL's location, ");
        printf("ErrorCode: %u\n\n", GetLastError());
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("\nDLL path: %s\n", dllPath);

    // hooks client's function
    bool isHookFound = false;
    for each (ProtoEntry rec in HookTable)
    {
        if (rec.build > buildNumber)
        {
			printf("Found %s hooks\n", rec.name);
			sendHook = Injector(baseAddress + hookEntry.send, rec.sendDetour, "Send hook");
			recvHook = Injector(baseAddress + hookEntry.recv, rec.recvDetour, "Recv hook");
            isHookFound = true;
            break;
        }
    }

    if (!isHookFound)
    {
        printf("Hooks not found!\n");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
        return 0;
    }

    // loops until SIGINT (CTRL-C) occurs
    while (!isSigIntOccured)
        Sleep(50); // sleeps 50 ms to be nice

    // unhooks functions
	sendHook.UnHook();
	recvHook.UnHook();

    // shutdowns the sniffer
    // note: after that DLL's entry point will be called with
    // reason DLL_PROCESS_DETACH
    FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    return 0;
}

void DumpPacket(DWORD packetType, DWORD connectionId, WORD opcodeSize, CDataStore* dataStore)
{
    mtx.lock();
    // gets the time
    time_t rawTime;
    time(&rawTime);

    DWORD tickCount = GetTickCount();

    DWORD optionalHeaderLength = 0;

    if (!fileDump)
    {
        tm* date = localtime(&rawTime);
        // basic file name format:
        char fileName[MAX_PATH];
        // removes the DLL name from the path
        PathRemoveFileSpec(dllPath);
        // fills the basic file name format
        _snprintf(fileName, MAX_PATH,
            "wowsniff_%s_%u_%d-%02d-%02d_%02d-%02d-%02d.pkt",
            locale, buildNumber,
            date->tm_year + 1900,
            date->tm_mon + 1,
            date->tm_mday,
            date->tm_hour,
            date->tm_min,
            date->tm_sec);

        // some info
        printf("Sniff dump: %s\n\n", fileName);

        char fullFileName[MAX_PATH];
        _snprintf(fullFileName, MAX_PATH, "%s\\%s", dllPath, fileName);

        WORD pkt_version    = PKT_VERSION;
        BYTE sniffer_id     = SNIFFER_ID;
        BYTE sessionKey[40] = { 0 };

        fileDump = fopen(fullFileName, "wb");
        // PKT 3.1 header
        fwrite("PKT",                           3, 1, fileDump);  // magic
        fwrite((WORD*)&pkt_version,             2, 1, fileDump);  // major.minor version
        fwrite((BYTE*)&sniffer_id,              1, 1, fileDump);  // sniffer id
        fwrite((DWORD*)&buildNumber,            4, 1, fileDump);  // client build
        fwrite(locale,                          4, 1, fileDump);  // client lang
        fwrite(sessionKey,                     40, 1, fileDump);  // session key
        fwrite((DWORD*)&rawTime,                4, 1, fileDump);  // started time
        fwrite((DWORD*)&tickCount,              4, 1, fileDump);  // started tick's
        fwrite((DWORD*)&optionalHeaderLength,   4, 1, fileDump);  // opional header length

        fflush(fileDump);
    }

    DWORD packetOpcode = opcodeSize == 4
        ? *(DWORD*)dataStore->buffer
        : *(WORD*)dataStore->buffer;

    BYTE* packetData     = dataStore->buffer + opcodeSize;
    DWORD packetDataSize = dataStore->size   - opcodeSize;

    fwrite((DWORD*)&packetType,             4, 1, fileDump);  // direction of the packet
    fwrite((DWORD*)&connectionId,           4, 1, fileDump);  // connection id
    fwrite((DWORD*)&tickCount,              4, 1, fileDump);  // timestamp of the packet
    fwrite((DWORD*)&optionalHeaderLength,   4, 1, fileDump);  // connection id
    fwrite((DWORD*)&dataStore->size,        4, 1, fileDump);  // size of the packet + opcode lenght
    fwrite((DWORD*)&packetOpcode,           4, 1, fileDump);  // opcode

    fwrite(packetData, packetDataSize,         1, fileDump);  // data

#if _DEBUG
    //printf("%s Opcode: 0x%04X Size: %-8u\n", packetType == CMSG ? "CMSG" : "SMSG", packetOpcode, packetDataSize);
#endif

    fflush(fileDump);

    mtx.unlock();
}

DWORD __fastcall SendHook(void* thisPTR, void* dummy , CDataStore* dataStore, DWORD connectionId)
{
    // dumps the packet
    DumpPacket(CMSG, connectionId, 4, dataStore);

    // unhooks the send function
	sendHook.UnHook();

    // now let's call client's function
    // so it can send the packet to the server (connection, CDataStore*, 2)
    DWORD returnValue = SendProto(sendHook.GetAddress())(thisPTR, dataStore, (void*)connectionId);

	sendHook.Hook();

    return 0;
}

#pragma region RecvHook

DWORD __fastcall RecvHook(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore)
{
    // packet dump
    DumpPacket(SMSG, 0, 2, dataStore);

    // unhooks the recv function
	recvHook.UnHook();

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto(recvHook.GetAddress())(thisPTR, param1, dataStore);

    // hooks again to catch the next incoming packets also
	recvHook.Hook();

    return returnValue;
}

DWORD __fastcall RecvHook_TBC(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3)
{
    // packet dump
    DumpPacket(SMSG, (DWORD)param3, 2, dataStore);

    // unhooks the recv function
	recvHook.UnHook();

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto_TBC(recvHook.GetAddress())(thisPTR, param1, dataStore, param3);

    // hooks again to catch the next incoming packets also
	recvHook.Hook();

    return returnValue;
}

DWORD __fastcall RecvHook_MOP(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3)
{
    // packet dump
    DumpPacket(SMSG, (DWORD)param3, 4, dataStore);

    // unhooks the recv function
	recvHook.UnHook();

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto_MOP(recvHook.GetAddress())(thisPTR, param1, dataStore, param3);

    // hooks again to catch the next incoming packets also
	recvHook.Hook();

    return returnValue;
}

DWORD __fastcall RecvHook_WOD(void* thisPTR, void* dummy, void* param1, void* param2, CDataStore* dataStore, void* param4)
{
    // packet dump
    DumpPacket(SMSG, (DWORD)param4, 4, dataStore);

    // unhooks the recv function
	recvHook.UnHook();

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto_WOD(recvHook.GetAddress())(thisPTR, param1, param2, dataStore, param4);

    // hooks again to catch the next incoming packets also
	recvHook.Hook();

    return returnValue;
}

#pragma endregion
