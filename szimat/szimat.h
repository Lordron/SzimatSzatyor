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
#include <mutex>
#include "ConsoleManager.h"
#include "Shared.h"
#include "Injector.h"

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
// that means: this pointer is passed via the ECX register
// fastcall convention means that the first 2 parameters is passed
// via ECX and EDX registers so the first param will be the this pointer and
// the second one is just a dummy (not used)
DWORD __fastcall SendHook(void* thisPTR, void*, CDataStore*, DWORD);

typedef DWORD(__thiscall *SendProto)(void*, void*, void*);

// this function will be called when recv called in the client
DWORD __fastcall RecvHook    (void* thisPTR, void* dummy, void* param1, CDataStore* dataStore);
DWORD __fastcall RecvHook_TBC(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3);
DWORD __fastcall RecvHook_MOP(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3);
DWORD __fastcall RecvHook_WOD(void* thisPTR, void* dummy, void* param1, void* param2, CDataStore* dataStore, void* param4);

typedef DWORD(__thiscall *RecvProto)    (void*, void*, void*);
typedef DWORD(__thiscall *RecvProto_TBC)(void*, void*, void*, void*);
typedef DWORD(__thiscall *RecvProto_MOP)(void*, void*, void*, void*);
typedef DWORD(__thiscall *RecvProto_WOD)(void*, void*, void*, void*, void*);

// basically this method controls what the sniffer should do
// pretty much like a "main method"
DWORD MainThreadControl(LPVOID /* param */);

char dllPath[MAX_PATH] = { 0 };
FILE* fileDump = 0;

Injector sendHook;
Injector recvHook;

typedef struct {
    WORD build;
    LPVOID sendDetour;
	LPVOID recvDetour;
	PCHAR name;
} ProtoEntry;

const ProtoEntry HookTable[] = {
    { 8606,   SendHook, RecvHook    , "Vanilla" },
    { 16135,  SendHook, RecvHook_TBC, "TBC"     },
    { 18443,  SendHook, RecvHook_MOP, "MOP"     },
    { 0xFFFF, SendHook, RecvHook_WOD, "WOD"     },
};