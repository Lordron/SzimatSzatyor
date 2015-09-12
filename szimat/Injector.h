#ifndef _Injector_h__
#define _Injector_h__

#include <iostream>
#include <Windows.h>

#ifdef _M_X64
#define JMP_INSTRUCTION_SIZE 12
#define INSTRUCTION_ADDRESS_OFFSET 2
#define INSTRUCTION_BYTECODE { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 }
#else
#define JMP_INSTRUCTION_SIZE 5
#define INSTRUCTION_ADDRESS_OFFSET 1
#define INSTRUCTION_BYTECODE { 0xE9, 0x00, 0x00, 0x00, 0x00 }
#endif

class Injector
{
private:
	DWORD_PTR hook;
	LPVOID detour;
	char* name;
	bool isWork;

	// global storage for the "the hooking" machine code
	BYTE hookCode[JMP_INSTRUCTION_SIZE];

	BYTE defaultCode[JMP_INSTRUCTION_SIZE];

	BYTE jumpMachineCode[JMP_INSTRUCTION_SIZE] = INSTRUCTION_BYTECODE;

	void WriteBlock(BYTE* buffer, BYTE* defaulBuffer = NULL)
	{
		// stores the old protection
		DWORD oldProtect;

		// changes the protection and gets the old one
		VirtualProtect((LPVOID)hook, JMP_INSTRUCTION_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);

		if (defaulBuffer != NULL)
			memcpy(defaulBuffer, (LPVOID)hook, JMP_INSTRUCTION_SIZE);

		// writes the original machine code to the address
		memcpy((LPVOID)hook, buffer, JMP_INSTRUCTION_SIZE);

		// flushes the cache
		FlushInstructionCache(GetCurrentProcess(), (LPVOID)hook, JMP_INSTRUCTION_SIZE);

		// restores the old protection
		VirtualProtect((LPVOID)hook, JMP_INSTRUCTION_SIZE, oldProtect, NULL);
	}
public:
	Injector() { }

	Injector(DWORD_PTR hook, LPVOID detour, char* name)
	{
		this->hook   = hook;
		this->detour = detour;
		this->name   = name;
		this->isWork = false;

        // calculates the displacement
        DWORD_PTR jmpDisplacement = (DWORD_PTR)detour - hook;

#ifndef _M_X64
        jmpDisplacement -= JMP_INSTRUCTION_SIZE;
#endif

        // be nice and nulls the displacement
        memset(&jumpMachineCode[INSTRUCTION_ADDRESS_OFFSET], 0x00, sizeof(LPVOID));
        // copies the "default" (no displacement yet) instruction
        memcpy(hookCode, jumpMachineCode, JMP_INSTRUCTION_SIZE);
        // copies the calculated value of the displacement
        memcpy(&hookCode[INSTRUCTION_ADDRESS_OFFSET], &jmpDisplacement, sizeof(LPVOID));

		WriteBlock(&hookCode[0], &defaultCode[0]);

		printf("%s is instaled!\n", this->name);
	}

	void Hook()	 
	{
		WriteBlock(&hookCode[0], NULL);
		if (!isWork)
		{
			printf("%s is working.\n", name);
			isWork = true;
		}
	}

	void UnHook()
	{
		WriteBlock(&defaultCode[0], NULL);
	}

    DWORD_PTR GetAddress() { return hook; }
};

#endif