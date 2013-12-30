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

#include <Windows.h>
#include <Shlwapi.h>

#include <cstdio>
#include <ctime>
#include "ConsoleManager.h"
#include "HookEntryManager.h"
#include "HookManager.h"
#include "FakePacket.h"

#define CMSG 0x47534D43 // client to server, CMSG
#define SMSG 0x47534D53 // server to client, SMSG

// static member initilization
volatile bool* ConsoleManager::_sniffingLoopCondition = NULL;

// needed to correctly shutdown the sniffer
HINSTANCE instanceDLL = NULL;
// true when a SIGINT occured
volatile bool isSigIntOccured = false;

// global access to the build number
WORD buildNumber = 0;
char locale[5] = { 'x', 'x', 'X', 'X', '\0' };

// this function will be called when send called in the client
// client has thiscall calling convention
// that means: this pointer is passed via the ECX register
// fastcall convention means that the first 2 parameters is passed
// via ECX and EDX registers so the first param will be the this pointer and
// the second one is just a dummy (not used)
DWORD __fastcall SendHook(void* thisPTR,
                          void* /* dummy */,
                          void* /* param1 */,
                          void* /* param2 */);
// this send prototype fits with the client's one
typedef DWORD (__thiscall *SendProto)(void*, void*, void*);

// address of WoW's send function
DWORD sendAddress = 0;
DWORD baseAddress = 0;

// global storage for the "the hooking" machine code which 
// hooks client's send function
BYTE machineCodeHookSend[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes machine code from the client's send function
BYTE defaultMachineCodeSend[JMP_INSTRUCTION_SIZE] = { 0 };

// this function will be called when recv called in the client
DWORD __fastcall RecvHook(void* thisPTR,
                          void* /* dummy */,
                          void* /* param1 */,
                          void* /* param2 */,
                          void* /* param3 */);
// this recv prototype fits with the client's one
typedef DWORD (__thiscall *RecvProto)(void*, void*, void*, void*);
// clients which has build number <= 8606 have different prototype
typedef DWORD (__thiscall *RecvProto8606)(void*, void*, void*);

// address of WoW's recv function
DWORD recvAddress = 0;
// global storage for the "the hooking" machine code which
// hooks client's recv function
BYTE machineCodeHookRecv[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes machine code from the client's recv function
BYTE defaultMachineCodeRecv[JMP_INSTRUCTION_SIZE] = { 0 };

// these are false if "hook functions" don't called yet
// and they are true if already called at least once
bool sendHookGood = false;
bool recvHookGood = false;

// basically this method controls what the sniffer should do
// pretty much like a "main method"
DWORD MainThreadControl(LPVOID /* param */);

char dllPath[MAX_PATH] = { 0 };
FILE* fileDump = 0;

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

    // inits the HookManager
    HookEntryManager::FillHookEntries();

    // gets the build number
    buildNumber = HookEntryManager::GetBuildNumberFromProcess();
    // error occured
    if (!buildNumber)
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("Detected build number: %hu\n", buildNumber);

    // checks this build is supported or not
    if (!HookEntryManager::IsHookEntryExists(buildNumber))
    {
        printf("ERROR: This build number is not supported.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // get the base address of the current process
    baseAddress = (DWORD)GetModuleHandle(NULL);

    DWORD localeAddress = HookEntryManager::GetHookEntry(buildNumber).locale_AddressOffset;
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
        printf("ErrorCode: %u\n\n",  GetLastError());
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("\nDLL path: %s\n", dllPath);

    // gets address of NetClient::Send2
    sendAddress = baseAddress + HookEntryManager::GetHookEntry(buildNumber).send2_AddressOffset;
    // hooks client's send function
    HookManager::Hook(sendAddress, (DWORD)SendHook, machineCodeHookSend, defaultMachineCodeSend);
    printf("Send is hooked.\n");

    // gets address of NetClient::ProcessMessage
    recvAddress = baseAddress + HookEntryManager::GetHookEntry(buildNumber).processMessage_AddressOffset;
    // hooks client's recv function
    HookManager::Hook(recvAddress, (DWORD)RecvHook, machineCodeHookRecv, defaultMachineCodeRecv);
    printf("Recv is hooked.\n");

    FakePacket fake(baseAddress);
    fake.SendCreatureQuery(100000);

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

static void DumpPacket(DWORD packetType, DWORD connectionId, DWORD packetOpcode, DWORD packetSize, DWORD buffer, const WORD initialReadOffset)
{
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
                  "%s\\wowsniff_%s_%u_%d-%02d-%02d_%02d-%02d-%02d.pkt",
                  dllPath, locale, buildNumber,
                  date->tm_year + 1900,
                  date->tm_mon + 1,
                  date->tm_mday,
                  date->tm_hour,
                  date->tm_min,
                  date->tm_sec);

        // some info
        printf("Sniff dump: %s\n\n", fileName);

        WORD pkt_version    = PKT_VERSION;
        BYTE sniffer_id     = SNIFFER_ID;
        DWORD tickCount     = GetTickCount();
        BYTE sessionKey[40] = { 0 };

        fileDump = fopen(fileName, "ab");
        // PKT 3.1 header
        fwrite("PKT",                         3, 1, fileDump);  // magic
        fwrite((WORD*)&pkt_version,           2, 1, fileDump);  // major.minor version
        fwrite((BYTE*)&sniffer_id,            1, 1, fileDump);  // sniffer id
        fwrite((DWORD*)&buildNumber,          4, 1, fileDump);  // client build
        fwrite(locale,                        4, 1, fileDump);  // client lang
        fwrite(sessionKey,                    40,1, fileDump);  // session key
        fwrite((DWORD*)&rawTime,              4, 1, fileDump);  // started time
        fwrite((DWORD*)&tickCount,            4, 1, fileDump);  // started tick's
        fwrite((DWORD*)&optionalHeaderLength, 4, 1, fileDump);  // opional header length

        fflush(fileDump);
    }

    DWORD fullSize = packetSize + initialReadOffset;

    fwrite((DWORD*)&packetType,           4, 1, fileDump);  // direction of the packet
    fwrite((DWORD*)&connectionId,         4, 1, fileDump);  // connection id
    fwrite((DWORD*)&rawTime,              4, 1, fileDump);  // timestamp of the packet
    fwrite((DWORD*)&optionalHeaderLength, 4, 1, fileDump);  // connection id
    fwrite((DWORD*)&fullSize,             4, 1, fileDump);  // size of the packet + opcode lenght
    fwrite((DWORD*)&packetOpcode,         4, 1, fileDump);  // opcode

    fwrite((BYTE*)(buffer + initialReadOffset), packetSize, 1, fileDump); // data

    fflush(fileDump);
}

DWORD __fastcall SendHook(void* thisPTR, void* /* dummy */, void* param1, void* param2)
{
    WORD packetOpcodeSize = 4; // 4 bytes for all versions

    DWORD buffer       = *(DWORD*)((DWORD)param1 + 4);
    DWORD packetOpcode = *(DWORD*)buffer;               // packetOpcodeSize
    DWORD packetSize   = *(DWORD*)((DWORD)param1 + 16); // totalLength, writePos

#if _DEBUG
    printf("CMSG Opcode: %u, Size: %u, param2: %u\n", packetOpcode, packetSize, param2);
#endif

    // dumps the packet
    DumpPacket(CMSG, 0, packetOpcode, packetSize - packetOpcodeSize, buffer, packetOpcodeSize);
    // unhooks the send function
    HookManager::UnHook(sendAddress, defaultMachineCodeSend);

    // now let's call client's function
    // so it can send the packet to the server (connection, CDataStore*, 2)
    DWORD returnValue = SendProto(sendAddress)(thisPTR, param1, param2);

    // hooks again to catch the next outgoing packets also
    HookManager::ReHook(sendAddress, machineCodeHookSend);

    if (!sendHookGood)
    {
        printf("Send hook is working.\n");
        sendHookGood = true;
    }

    return 0;
}

DWORD __fastcall RecvHook(void* thisPTR, void* /* dummy */, void* param1, void* param2, void* param3)
{
    // 2 bytes before MOP, 4 bytes after MOP
    WORD packetOpcodeSize = buildNumber <= WOW_MOP_16135 ? 2 : 4; 

    DWORD buffer       = *(DWORD*)((DWORD)param2 + 4);
    DWORD packetOpcode = packetOpcodeSize == 2 ? *(WORD*) buffer  // 2 bytes
                                               : *(DWORD*)buffer; // or 4 bytes
    DWORD packetSize   = *(DWORD*)((DWORD)param2 + 16);           // totalLength, writePos

#if _DEBUG
    printf("SMSG Opcode: %u, Size: %u, param1: %u, param3: %u\n", packetOpcode, packetSize, param1, param3);
#endif

    // packet dump
    DumpPacket(SMSG, 0, packetOpcode, packetSize - packetOpcodeSize, buffer, packetOpcodeSize);

    // unhooks the recv function
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = 0;
    if (buildNumber <= WOW_TBC_8606) // different prototype
        returnValue = RecvProto8606(recvAddress)(thisPTR, param1, param2);
    else
        returnValue = RecvProto(recvAddress)(thisPTR, param1, param2, param3);

    // hooks again to catch the next incoming packets also
    HookManager::ReHook(recvAddress, machineCodeHookRecv);

    if (!recvHookGood)
    {
        printf("Recv hook is working.\n");
        recvHookGood = true;
    }

    return returnValue;
}
