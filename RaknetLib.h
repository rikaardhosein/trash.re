#include <cstdio>
#include <cstdlib>
#include <winsock2.h>
#include <windows.h>

typedef unsigned char BYTE;

// We can get away with this because there's a
// static member function that will handle the
// allocation for us and give us a pointer.
typedef void RakPeer;

/*
Cut from IDA Pro disassembly:

-------------------------------------------------------------------------------
var_34= word ptr -34h
var_10= dword ptr -10h
<...>
lea     ecx, [esp+5Ch+var_34] ; this
call    ??0SocketDescriptor@@QAE@XZ ; SocketDescriptor::SocketDescriptor(void)
-------------------------------------------------------------------------------

The compiler allocated 36 bytes on the stack for the SocketDesciptor.
We will allocate at least 36 bytes. I don't know how many bytes of padding the
compiler will decide to use but once we have >=36 bytes, we should be fine.

We don't actually need to know what the properties are inside the struct since we'll
just be passing pointers around.
*/
struct SocketDescriptor
{
    unsigned char filler[72];
};


#pragma pack(1)
struct SystemAddress {
    unsigned int ip;
    // unsigned short port;
    unsigned int port;
};


/*
0100D35B | FFD2                     | call edx                                                                          | RakPeer:Receive
0100D35D | 8BF8                     | mov edi,eax                                                                       | 
0100D35F | 85FF                     | test edi,edi                                                                      |
0100D361 | 0F84 C1000000            | je netlib.100D428                                                                 |
0100D367 | 8B47 14                  | mov eax,dword ptr ds:[edi+14]                                                     |  Offset to data ptr
0100D36A | 8038 4B                  | cmp byte ptr ds:[eax],4B                                                          | 
*/


/*
02DAEDC8  00 00 DA 02 42 2D E6 1B F3 5E 00 00 01 00 00 00  ..Ú.B-æ.ó^......    | Since we know where the data ptr is, and we know that length in bytes is supposed to be followed by length in bits and 
02DAEDD8  08 00 00 00 E4 ED DA 02 00 00 00 00 13 00 00 00  ....äíÚ.........    | both of these come right before it, length (in bytes) is @ offset 12, length(in bits) is at offset 16
*/
#pragma pack(1)
struct Packet {
    char filler[12];
    unsigned int byte_len;
    unsigned int bit_len;
    BYTE *data;
};



extern HMODULE raknet;

void init_raknet();

RakPeer *raknet_get_rakpeer_interface();

SocketDescriptor *raknet_get_socket_descriptor();

bool raknet_rakpeer_startup(RakPeer *rakpeer, SocketDescriptor *socket);

bool raknet_rakpeer_connect(RakPeer *rakpeer, char *host, unsigned int port);

bool raknet_rakpeer_send(RakPeer *rakpeer, BYTE *data, unsigned int len);

Packet* raknet_rakpeer_receive(RakPeer *rakpeer);

void raknet_rakpeer_deallocate_packet(RakPeer *rakpeer, Packet *p);
