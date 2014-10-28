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

#pragma once

#if _WIN64
    #define JMP_INSTRUCTION_SIZE 12

    // mov rax ... size
    #define JMP_OPCODE_SIZE 2

    // mov rax, [displacement]
    // jmp rax
    BYTE jumpMachineCode[JMP_INSTRUCTION_SIZE] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
#else
    #define JMP_INSTRUCTION_SIZE 5

    // jmp ... size
    #define JMP_OPCODE_SIZE 1

    // jmp [displacement]
    BYTE jumpMachineCode[JMP_INSTRUCTION_SIZE] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
#endif

// functions which can hook/unhook functions
class HookManager
{
public:
    // hooks a function located at hookedFunctionAddress
    // hookedFunctionAddress - the function on this address will be hooked so
    // the WoW contains this function
    // hookFunctionAddress - this is the user defined "callback" function
    // which will be called on hook
    static void Hook(DWORD_PTR hookedFunctionAddress, DWORD_PTR hookFunctionAddress, BYTE* hookMachineCode, BYTE* defaultMachineCode)
    {
        // calculates the displacement
        DWORD_PTR jmpDisplacement = hookFunctionAddress - hookedFunctionAddress - JMP_INSTRUCTION_SIZE;

        // be nice and nulls the displacement
        memset(&jumpMachineCode[JMP_OPCODE_SIZE], 0x00, sizeof(void*));
        // copies the "default" (no displacement yet) instruction
        memcpy(hookMachineCode, jumpMachineCode, JMP_INSTRUCTION_SIZE);
        // copies the calculated value of the displacement
        memcpy(&hookMachineCode[JMP_OPCODE_SIZE], &jmpDisplacement, sizeof(void*));

        HookManager::WriteBlock(hookedFunctionAddress, hookMachineCode, defaultMachineCode);
    }

    static void WriteBlock(DWORD_PTR address, BYTE* buffer, BYTE* defaulBuffer = NULL)
    {
        // stores the old protection
        DWORD oldProtect;

        // changes the protection and gets the old one
        VirtualProtect((LPVOID)address, JMP_INSTRUCTION_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);

        if (defaulBuffer != NULL)
            memcpy(defaulBuffer, (LPVOID)address, JMP_INSTRUCTION_SIZE);

        // writes the original machine code to the address
        memcpy((LPVOID)address, buffer, JMP_INSTRUCTION_SIZE);

        // flushes the cache
        FlushInstructionCache(GetCurrentProcess(), (LPVOID)address, JMP_INSTRUCTION_SIZE);

        // restores the old protection
        VirtualProtect((LPVOID)address, JMP_INSTRUCTION_SIZE, oldProtect, NULL);
    }
};
