#include "RaknetLib.h"

/*
So most of the functions being reverse engineered
use the __thiscall convention. On M$ compilers, this
is almost identical to __stdcall except for ecx
shenanigans.

So we'll handle the ecx shenanigans ourself ("this ptr")
and use the two macros below to make sure we restore
any registers that are used by the functions.
*/
#define STDCALL_ENTER \
    push eax;         \
    push ecx;         \
    push edx;

#define STDCALL_LEAVE \
    pop edx;          \
    pop ecx;          \
    pop eax;

HMODULE raknet = NULL;
struct SystemAddress UNASSIGNED_SYSTEM_ADDRESS = {0xFFFFFFFF, 0x0000FFFF};
  

void init_raknet()
{
    raknet = LoadLibraryA("./RakNet.dll");
}

RakPeer *raknet_get_rakpeer_interface()
{
    typedef RakPeer *(_cdecl * GRPI)();
    static GRPI GetRakPeerInterface = NULL;
    if (!GetRakPeerInterface)
        GetRakPeerInterface = (GRPI)GetProcAddress(raknet, "?GetRakPeerInterface@RakNetworkFactory@@SAPAVRakPeerInterface@@XZ");
    return GetRakPeerInterface();
}

SocketDescriptor *raknet_get_socket_descriptor()
{
    // We don't have to create a fp with any calling convention since we're calling this
    // from our inline asm and we should be handling register and stack management ourselves.
    static void *GetSocketDescriptor = NULL;
    if (!GetSocketDescriptor)
        GetSocketDescriptor = (void *)GetProcAddress(raknet, "??0SocketDescriptor@@QAE@XZ");

    SocketDescriptor *socket = (SocketDescriptor *)malloc(sizeof(SocketDescriptor));

    // From the disassembly, this was most likely compiled with a M$ compiler since
    // the "this" pointer is passed in via ecx.Therefore, the callee cleans the stack
    // (and we're not pushing anything onto the stack anyway because we're using ecx for "this")
    __asm {
        STDCALL_ENTER
        mov ecx, socket;
        call GetSocketDescriptor;
        STDCALL_LEAVE
    }

    return socket;
}

// We're cheating a bit with these return values. The return value for Raknet::Startup is typically
// part of an enum {} but we really only care if the function succeeds (returns 0)
bool raknet_rakpeer_startup(RakPeer *rakpeer, SocketDescriptor *socket)
{
    static void *Startup = NULL;
    if (!Startup)
        Startup = (void *)GetProcAddress(raknet, "?Startup@RakPeer@@UAE_NGHPAUSocketDescriptor@@I@Z");

    bool result = false;

    __asm {
        STDCALL_ENTER

        mov ecx, rakpeer;
        push 1;
        mov edx, socket;
        push edx;
        push 30;
        push 1;
        call Startup;

        mov result, al;
        STDCALL_LEAVE
    }

    // Returns 0 on success, so inv
    return !result;
}

// Just like with Raknet::Startup, we're going to be cheating with our return value.
// We just want to know if it succeeded (returned 0). We don't care about different error codes (for now).
bool raknet_rakpeer_connect(RakPeer *rakpeer, char *host, unsigned int port)
{
    static void *Connect = NULL;
    if (!Connect)
        Connect = (void *)GetProcAddress(raknet, "?Connect@RakPeer@@UAE_NPBDG0HI@Z");
    bool result = false;

    __asm {
        STDCALL_ENTER
        mov ecx, rakpeer;
        push 0;
        push 0;
        push 0;
        push port;
        push host;
        call Connect;
        mov result, al;
        STDCALL_LEAVE
    }

    // Returns 0 on success, so inv
    return !result;
}

bool raknet_rakpeer_send(RakPeer *rakpeer, BYTE *data, unsigned int len)
{
    // Returns 0 on bad input
    static void *Send = NULL;
    if (!Send)
        Send = (void *)GetProcAddress(raknet, "?Send@RakPeer@@UAE_NPBDHW4PacketPriority@@W4PacketReliability@@DUSystemAddress@@_N@Z");
    bool result = false;

    __asm {
        STDCALL_ENTER
        mov ecx, rakpeer;
        push 1;
        push UNASSIGNED_SYSTEM_ADDRESS.port;
        push UNASSIGNED_SYSTEM_ADDRESS.ip;
        push 0;
        push 3;
        push 1;
        push len;
        push data;
        call Send;
        mov result, al;
        STDCALL_LEAVE
    }

    return result;
}

Packet *raknet_rakpeer_receive(RakPeer *rakpeer)
{
    static void *Receive = NULL;
    if (!Receive)
        Receive = (void *)GetProcAddress(raknet, "?Receive@RakPeer@@UAEPAUPacket@@XZ");
    Packet *p = NULL;

    __asm {
        STDCALL_ENTER
        mov ecx, rakpeer;
        call Receive;
        mov p, eax;
        STDCALL_LEAVE
    }

    return p;
}

void raknet_rakpeer_deallocate_packet(RakPeer *rakpeer, Packet *p)
{
    static void *DeallocatePacket = NULL;
    if (!DeallocatePacket)
        DeallocatePacket = (void *)GetProcAddress(raknet, "?DeallocatePacket@RakPeer@@UAEXPAUPacket@@@Z");

    __asm {
        STDCALL_ENTER
        mov ecx, rakpeer;
        push p;
        call DeallocatePacket;
        STDCALL_LEAVE
    }
}