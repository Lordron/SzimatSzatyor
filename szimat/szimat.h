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
#include "Shared.h"
#include "HookManager.h"
#include <mutex>

#define PKT_VERSION 0x0301
#define SNIFFER_ID  15

#define CMSG 0x47534D43 // client to server, CMSG
#define SMSG 0x47534D53 // server to client, SMSG

// static member initilization
volatile bool* ConsoleManager::_sniffingLoopCondition = NULL;

std::mutex mtx;

// needed to correctly shutdown the sniffer
HINSTANCE instanceDLL = NULL;
// true when a SIGINT occured
volatile bool isSigIntOccured = false;

// global access to the build number
WORD buildNumber = 0;
char locale[5] = { 'x', 'x', 'X', 'X', '\0' };
HookEntry hookEntry;

// this function will be called when send called in the client
// client has thiscall calling convention
// that means: this pointer is passed via the ECX/RCX register
// fastcall convention means that the first 2 parameters is passed
// via ECX/RCX and EDX/RDX registers so the first param will be the this pointer and
// the second one is just a dummy (not used)
DWORD __fastcall SendHook(void* thisPTR, void*, CDataStore*, DWORD);

typedef DWORD(__thiscall *SendProto)(void*, void*, DWORD);

// address of WoW's send function
DWORD sendAddress = 0;
// global storage for the "the hooking" machine code which 
// hooks client's send function
BYTE machineCodeHookSend[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes for x86 or 12 bytes for x64 machine code
// from the client's send function
BYTE defaultMachineCodeSend[JMP_INSTRUCTION_SIZE] = { 0 };

// this function will be called when recv called in the client
DWORD __fastcall RecvHook3(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore);
DWORD __fastcall RecvHook4(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3);
DWORD __fastcall RecvHook5(void* thisPTR, void* dummy, void* param1, void* param2, CDataStore* dataStore, void* param4);

typedef DWORD(__thiscall *RecvProto3)(void*, void*, void*);
typedef DWORD(__thiscall *RecvProto4)(void*, void*, void*, void*);
typedef DWORD(__thiscall *RecvProto5)(void*, void*, void*, void*, void*);

// address of WoW's recv function
DWORD recvAddress = 0;
// global storage for the "the hooking" machine code which
// hooks client's recv function
BYTE machineCodeHookRecv[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes for x86 or 12 bytes for x64 machine code
// from the client's recv function
BYTE defaultMachineCodeRecv[JMP_INSTRUCTION_SIZE] = { 0 };

// these are false if "hook functions" don't called yet
// and they are true if already called at least once
bool sendHookGood = false;
bool recvHookGood = false;

// basically this method controls what the sniffer should do
// pretty much like a "main method"
DWORD MainThreadControl(LPVOID /* param */);

char dllPath[MAX_PATH] = { 0 };
FILE* fileDump = NULL;