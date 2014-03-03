#pragma once
#include "def.h"

#define CMSG_CREATURE_QUERY_OFFSET 0x002915FD // opcode 0x1E72
#define CMSG_QUEST_POI_QUERY       0x66675B
#define INIT_QUEST_POI_QUERY       0
#define CDATA_STORE_PUT_INT32      0x010135
#define CDATA_STORE_FINALIZE       0x29BA0E
#define CLIENT_SERVICES_SEND2      0x009FC1

typedef struct
{
    virtual void Dummy() { };    // to create vtable
    BYTE *m_buffer;
    DWORD m_base;
    DWORD m_alloc;
    DWORD m_size;
    DWORD m_read;
    DWORD dword_24;
    DWORD dword_28;
} CDataStore;

typedef void(__cdecl *CMSG_CREATURE_QUERY)      (void* entry);

typedef CDataStore* (__thiscall *InitializePtr) (CDataStore *pData);

typedef void(__cdecl *SendQuestPoiQuery)        (CDataStore *pData);

typedef CDataStore& (__thiscall *PutInt32Ptr)   (CDataStore *pData, DWORD val);
typedef void(__thiscall *DestroyPtr)            (CDataStore *pData);

class FakePacket
{
public:
    FakePacket(int i) {}

    void FakePacket::SendCreatureQuery(int max_entry)
    {
        for (int entry = 1; entry < max_entry; ++entry)
        {
            CMSG_CREATURE_QUERY(baseAddress + CMSG_CREATURE_QUERY_OFFSET)(&entry);
            printf("CMSG_CREATURE_QUERY(0x%08X)(%i)\n", baseAddress + CMSG_CREATURE_QUERY_OFFSET, entry);
            if (isSigIntOccured)
                break;
            Sleep(50);
        }
    }

    void FakePacket::SendQuestPOIQuery(int max_entry)
    {
        for (int entry = 1; entry < max_entry;)
        {
            CDataStore packet;

            InitializePtr(0)(&packet);

            PutInt32Ptr(baseAddress + CDATA_STORE_PUT_INT32)(&packet, CMSG_QUEST_POI_QUERY);
            PutInt32Ptr(baseAddress + CDATA_STORE_PUT_INT32)(&packet, 10 * 4); // 22 bit

            for (int i = 0; i < 10; ++i, ++entry)
            {
                PutInt32Ptr(baseAddress + CDATA_STORE_PUT_INT32)(&packet, entry); // 22 bit
            }

            printf("Send packet CMSG_QUEST_POI_QUERY, entry %i\n", entry);
            SendQuestPoiQuery(baseAddress + CLIENT_SERVICES_SEND2)(&packet);
            
            if (isSigIntOccured)
                break;
            Sleep(50);
        }
    }
};