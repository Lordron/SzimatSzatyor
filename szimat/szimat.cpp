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
    printf("http://github.com/Anubisss/SzimatSzatyor\n\n");

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

    DWORD localeAddress = hookEntry.locale;
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

    // gets address of NetClient::Send2
    sendAddress = baseAddress + hookEntry.send_2;
    // hooks client's send function
    HookManager::Hook(sendAddress, (DWORD_PTR)SendHook, machineCodeHookSend, defaultMachineCodeSend);
    printf("Send is hooked.\n");

    // gets address of NetClient::ProcessMessage
    recvAddress = baseAddress + hookEntry.recive;
    // hooks client's recv function

    if (buildNumber < 8606)
    {
        HookManager::Hook(recvAddress, (DWORD_PTR)RecvHook3, machineCodeHookRecv, defaultMachineCodeRecv);
    }
    else if (buildNumber < 19000)
    {
        HookManager::Hook(recvAddress, (DWORD_PTR)RecvHook4, machineCodeHookRecv, defaultMachineCodeRecv);
    }
    else
    {
        HookManager::Hook(recvAddress, (DWORD_PTR)RecvHook5, machineCodeHookRecv, defaultMachineCodeRecv);
    }

    printf("Recv is hooked.\n");

    if (hookEntry.npc_qw > 0)
    {
        GetAllCreatures(hookEntry.npc_qw + baseAddress, 100000);
    }

    // loops until SIGINT (CTRL-C) occurs
    while (!isSigIntOccured)
        Sleep(50); // sleeps 50 ms to be nice

    // unhooks functions
    HookManager::UnHook(sendAddress, defaultMachineCodeSend);
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // shutdowns the sniffer
    // note: after that DLL's entry point will be called with
    // reason DLL_PROCESS_DETACH
    FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    return 0;
}

void DumpPacket(DWORD64 packetType, DWORD connectionId, WORD opcodeSize, CDataStore* dataStore)
{
    mtx.lock();
    // gets the time
    time_t rawTime;
    time(&rawTime);
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
        DWORD tickCount     = GetTickCount();
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
    fwrite((DWORD*)&rawTime,                4, 1, fileDump);  // timestamp of the packet
    fwrite((DWORD*)&optionalHeaderLength,   4, 1, fileDump);  // connection id
    fwrite((DWORD*)&dataStore->size,        4, 1, fileDump);  // size of the packet + opcode lenght
    fwrite((DWORD*)&packetOpcode,           4, 1, fileDump);  // opcode

    fwrite(packetData, packetDataSize,         1, fileDump);  // data

#if _DEBUG
    printf("%s Opcode: %-8u Size: %-8u\n", &packetType, packetOpcode, packetDataSize);
#else
    printf("Packet count CMSG: %u SMSG: %u\r", CMSG_packetCount, SMSG_packetCount);
#endif

    fflush(fileDump);

    mtx.unlock();
}

DWORD __fastcall SendHook(void* thisPTR, void* dummy , CDataStore* dataStore, DWORD connectionId)
{
    ++CMSG_packetCount;
    // dumps the packet
    DumpPacket(CMSG, (DWORD)connectionId, 4, dataStore);

    // unhooks the send function
    HookManager::UnHook(sendAddress, defaultMachineCodeSend);

    // now let's call client's function
    // so it can send the packet to the server (connection, CDataStore*, 2)
    DWORD returnValue = SendProto(sendAddress)(thisPTR, dataStore, connectionId);

    // hooks again to catch the next outgoing packets also
    HookManager::ReHook(sendAddress, machineCodeHookSend);

    if (!sendHookGood)
    {
        printf("Send hook is working.\n");
        sendHookGood = true;
    }

    return 0;
}

#pragma region RecvHook

DWORD __fastcall RecvHook3(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore)
{
    ++SMSG_packetCount;
    // packet dump
    DumpPacket(SMSG, 0, 2, dataStore);

    // unhooks the recv function
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto3(recvAddress)(thisPTR, param1, dataStore);

    // hooks again to catch the next incoming packets also
    HookManager::ReHook(recvAddress, machineCodeHookRecv);

    if (!recvHookGood)
    {
        printf("Recv hook3 is working.\n");
        recvHookGood = true;
    }

    return returnValue;
}

DWORD __fastcall RecvHook4(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3)
{
    ++SMSG_packetCount;
    WORD opcodeSize = buildNumber <= WOW_MOP_16135 ? 2 : 4;
    // packet dump
    DumpPacket(SMSG, (DWORD)param3, opcodeSize, dataStore);

    // unhooks the recv function
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto4(recvAddress)(thisPTR, param1, dataStore, param3);

    // hooks again to catch the next incoming packets also
    HookManager::ReHook(recvAddress, machineCodeHookRecv);

    if (!recvHookGood)
    {
        printf("Recv hook4 is working.\n");
        recvHookGood = true;
    }

    return returnValue;
}

DWORD __fastcall RecvHook5(void* thisPTR, void* dummy, void* param1, void* param2, CDataStore* dataStore, void* param4)
{
    ++SMSG_packetCount;
    // packet dump
    DumpPacket(SMSG, (DWORD)param4, 4, dataStore);

    // unhooks the recv function
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto5(recvAddress)(thisPTR, param1, param2, dataStore, param4);

    // hooks again to catch the next incoming packets also
    HookManager::ReHook(recvAddress, machineCodeHookRecv);

    if (!recvHookGood)
    {
        printf("Recv hook5 is working.\n");
        recvHookGood = true;
    }

    return returnValue;
}

#pragma endregion

void GetAllCreatures(DWORD_PTR address, DWORD max_entry)
{
    printf("Started Creature linking [1 - %u]\n\n", max_entry);

    for (DWORD entry = 1; entry < max_entry; ++entry)
    {
        CreatureQueryProto(address+0)(&entry);
        printf("CMSG_CREATURE_QUERY %i\t", entry);

        if (isSigIntOccured)
            break;
        Sleep(50);
    }
}