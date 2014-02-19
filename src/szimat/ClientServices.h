#pragma once
#include "CDataStore.h"

typedef void  (__cdecl *SendPacketPtr)(CDataStore *pData);

class ClientServices
{
private:
    static SendPacketPtr fpSendPacket;
public:
    static void SendGamePacket(CDataStore *pData)
    {
        pData->Finalize();
        fpSendPacket(pData);
    }

    static void Init(DWORD dwBaseAddress)
    {
        void(*ClientServices::fpSendPacket)(CDataStore *pData) = reinterpret_cast<SendPacketPtr> (dwBaseAddress + 0x00664239);
    }
};