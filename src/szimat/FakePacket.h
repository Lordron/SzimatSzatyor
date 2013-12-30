#pragma once

#define CMSG_CREATURE_QUERY_OFFSET 0x001FFA75

typedef void(__cdecl *CMSG_CREATURE_QUERY)(void* entry);

class FakePacket
{
private:
    DWORD baseAddress;
public:
    FakePacket(DWORD base)
    {
        baseAddress = base;
    }

    void FakePacket::SendCreatureQuery(int max_entry)
    {
        for (int entry = 1; entry < max_entry; ++entry)
        {
            CMSG_CREATURE_QUERY(baseAddress + CMSG_CREATURE_QUERY_OFFSET)(&entry);

            printf("CMSG_CREATURE_QUERY(0x%08X)(%i)\n",
                baseAddress + CMSG_CREATURE_QUERY_OFFSET, entry);

            Sleep(50);
        }
    }
};