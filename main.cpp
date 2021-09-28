#include <cstdio>
#include <string>
#include <cstdlib>
#include <queue>
#include <iostream>
#include <process.h>
#include "PacketTypes.h"
#include "RaknetLib.h"

using namespace std;

#define NETWORK_LOOP_SLEEP_INTERVAL 10

typedef unsigned char BYTE;
typedef void RakPeer;
unsigned int timer = 0;
bool is_connected = false;
CRITICAL_SECTION message_queue_cs;

struct msg
{
    BYTE *data;
    unsigned int len;
};

queue<msg *> message_queue;
RakPeer *rakpeer;

PacketType get_packet_type(Packet *p)
{
    BYTE *data = p->data;
    if (data)
    {
        return (PacketType)data[0];
    }
    return PacketType::ID_INVLAID;
}

void NetworkUpdateLoop()
{
    while (true)
    {

        if (is_connected)
        {
            if (TryEnterCriticalSection(&message_queue_cs))
            {
                if (timer == 5000)
                {
                    raknet_rakpeer_send(rakpeer, (BYTE *)"\x4b\xff", 2);
                    timer = 0;
                }
                while (!message_queue.empty())
                {
                    msg *m = message_queue.front();
                    raknet_rakpeer_send(rakpeer, m->data, m->len);
                    message_queue.pop();
                    free(m->data);
                    free(m);
                }
                LeaveCriticalSection(&message_queue_cs);
            }
        }

        Packet *p = NULL;
        for (p = raknet_rakpeer_receive(rakpeer); p; raknet_rakpeer_deallocate_packet(rakpeer, p), p = raknet_rakpeer_receive(rakpeer))
        {
            PacketType pt = get_packet_type(p);
            BYTE *data = p->data;
            switch (pt)
            {
            case PacketType::ID_CONNECTION_REQUEST_ACCEPTED:
                is_connected = true;
                printf("Connection accepted!\n");
                break;
            case PacketType::TRASH_LOBBY_MESSAGE:
                ++data; 
                if(data[0] == '\x25' && data[1] == '\x01') {
                    
                    data += 2;
                    int username_len = strlen((char*)data);
                    char *username = (char*)malloc(username_len+1);
                    strncpy(username, (char*)data, username_len);
                    username[username_len] = '\x00';

                    data += (username_len+1);
                    int msg_len = strlen((char*)data);
                    char *chatmsg = (char*)malloc(msg_len+1);
                    strncpy(chatmsg, (char*)data, msg_len);
                    chatmsg[msg_len] = '\x00';
                    printf("%s: %s\n", username, chatmsg);
                    free(username);
                    free(chatmsg);

                }
                break;
            };
        }

        Sleep(NETWORK_LOOP_SLEEP_INTERVAL);
        timer += 10;
    }
}

void send_message(BYTE *data, unsigned int len)
{
    msg *m = (msg *)malloc(sizeof(msg));
    BYTE *copy = (BYTE *)malloc(len);
    memcpy(copy, data, len);
    m->data = copy;
    m->len = len;
    message_queue.push(m);
}

int main()
{

    InitializeCriticalSection(&message_queue_cs);
    init_raknet();
    rakpeer = raknet_get_rakpeer_interface();
    SocketDescriptor *socket = raknet_get_socket_descriptor();
    bool result = raknet_rakpeer_startup(rakpeer, socket);

    uintptr_t t = _beginthread((_beginthread_proc_type)NetworkUpdateLoop, 0, NULL);
    if (t == -1)
    {
        printf("Failed to create thread!\n");
    }

    result = raknet_rakpeer_connect(rakpeer, "lobby.inhumangames.com", 24307);

    //send pkt 1
    send_message((BYTE *)"Lchatclient2", 12);

    //send pkt 2
    send_message((BYTE *)"K"
                         "\x0D"
                         "\x31"
                         "\x35Jan14\x00password\x00\xe1\x0e\x71\x9a\x00\xc7\xae\x40\xe5\x5b\x6d\x53\x00",
                 32);

    while (true)
    {
        string chatmsg;
        getline(cin,chatmsg);

        chatmsg = "\x4b\x0e" + chatmsg;
        send_message((BYTE *)chatmsg.c_str(), chatmsg.length() + 1);
    }

    DeleteCriticalSection(&message_queue_cs);
}