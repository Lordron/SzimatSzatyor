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
#include <wtypes.h>
#include <map>

#define WOW_TBC_8606  8606
#define WOW_MOP_16135 16135

// stores and manages hook entries
// this will be compiled into a static lib
// so both of the injector and the DLL too can use this class
class HookEntryManager
{
public:
    // hook entry structure
    // stores the offsets which are will be hooked
    // every different client version should has different offsets
    struct HookEntry
    {
        // offset of NetClient::Send2 to sniff client packets
        DWORD send;
        // offset of NetClient::ProcessMessage to sniff server packets
        DWORD recive;
        // offset of client locale "xxXX"
        DWORD locale;
    };

    // returns the build number of the client
    // returns 0 if an error occurred
    // (gets this from file version info of client's exe)
    //
    // param should be NULL when would like to get the
    // path of the _current_ process' executable
    // this means the sniffer should call this with NULL because
    // the sniffer is just a "thread" which running in WoW
    //
    // param should NOT be NULL when would like to get the
    // path of an _external_ process' executable
    // so in the injector the param should contain the handle of a WoW process
    static WORD GetBuildNumberFromProcess(HANDLE hProcess = NULL);

    //
    static bool GetOffsets(const HINSTANCE moduleHandle, const WORD build, HookEntry* entry);

    // returns true if hook entry exists for this specified build number
    // otherwise false
    static bool IsHookEntryExists(const HINSTANCE moduleHandle, WORD buildNumber)
    {
        HookEntry entry;
        return GetOffsets(moduleHandle, buildNumber, &entry);
    }
};
