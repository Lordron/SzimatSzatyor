#pragma once
#include <cstdio>
#include <ctime>
#include <Windows.h>

class CDataStore;

typedef CDataStore* (__thiscall *InitializePtr) (CDataStore *pData);
typedef CDataStore& (__thiscall *PutInt8Ptr)    (CDataStore *pData, BYTE val);
typedef CDataStore& (__thiscall *PutInt16Ptr)   (CDataStore *pData, WORD val);
typedef CDataStore& (__thiscall *PutInt32Ptr)   (CDataStore *pData, DWORD val);
typedef CDataStore& (__thiscall *PutFloatPtr)   (CDataStore *pData, float val);
typedef CDataStore& (__thiscall *PutBytesPtr)   (CDataStore *pData, BYTE* pBuf, DWORD size);

typedef void(__thiscall *FinalizePtr)           (CDataStore *pData);
typedef void(__thiscall *DestroyPtr)            (CDataStore *pData);

class CDataStore
{
private:
    virtual void Dummy() { };    // to create vtable

    BYTE *m_buffer;
    DWORD m_base;
    DWORD m_alloc;
    DWORD m_size;
    DWORD m_read;

    static InitializePtr fpInit;
    static PutInt8Ptr fpPutInt8;
    static PutInt16Ptr fpPutInt16;
    static PutInt32Ptr fpPutInt32;
    static PutFloatPtr fpPutFloat;
    static PutBytesPtr fpPutBytes;
    static FinalizePtr fpFinalize;
    static DestroyPtr fpDestroy;

public:
    CDataStore()    { fpInit(this);     }
    ~CDataStore()   { fpDestroy(this);  }
    void Finalize() { fpFinalize(this); }

    CDataStore(DWORD msg)
    {
        fpInit(this);
        fpPutInt32(this, msg);
    }

    CDataStore& PutInt8(BYTE val)   { return fpPutInt8( this, val); }
    CDataStore& PutInt16(WORD val)  { return fpPutInt16(this, val); }
    CDataStore& PutInt32(DWORD val) { return fpPutInt32(this, val); }
    CDataStore& PutFloat(float val) { return fpPutFloat(this, val); }

    CDataStore& PutPutBytes(BYTE* pBuf, DWORD size)
    {
        return fpPutBytes(this, pBuf, size);
    }

    static void InitOffsets(DWORD dwDaseAddr)
    {
        CDataStore* (__thiscall *CDataStore::fpInit)     (CDataStore *pData) = reinterpret_cast<InitializePtr>(dwDaseAddr + 0x00401050);
        CDataStore& (__thiscall *CDataStore::fpPutInt8)  (CDataStore *pData, BYTE val)  = reinterpret_cast<PutInt8Ptr> (dwDaseAddr + 0xF003);
        CDataStore& (__thiscall *CDataStore::fpPutInt16) (CDataStore *pData, WORD val)  = reinterpret_cast<PutInt16Ptr>(dwDaseAddr + 0xF030);
        CDataStore& (__thiscall *CDataStore::fpPutInt32) (CDataStore *pData, DWORD val) = reinterpret_cast<PutInt32Ptr>(dwDaseAddr + 0xF060);
        CDataStore& (__thiscall *CDataStore::fpPutFloat) (CDataStore *pData, float val) = reinterpret_cast<PutFloatPtr>(dwDaseAddr + 0xF0C3);
        CDataStore& (__thiscall *CDataStore::fpPutBytes) (CDataStore *pData, BYTE* pBuf, DWORD size) = reinterpret_cast<PutBytesPtr>(dwDaseAddr + 0xF1FA);

        void(__thiscall *CDataStore::fpFinalize)         (CDataStore *pData) = reinterpret_cast<FinalizePtr>(dwDaseAddr + 0x00401130);
        void(__thiscall *CDataStore::fpDestroy)          (CDataStore *pData) = reinterpret_cast<DestroyPtr> (dwDaseAddr + 0x8F48);
    }    
};