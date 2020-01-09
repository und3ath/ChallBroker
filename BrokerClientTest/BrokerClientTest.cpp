// BrokerClientTest.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <iostream>
#include <WinSock2.h>

#include "../sockduplib/sockduplib.h"



int main(int argc, char** argv)
{
    char szBuf[MAX_PATH + 1];
    WSABUF wsaBuf;
    DWORD dwReceived = 0;
    DWORD dwFlags = 0;
    int nStatus;

    SOCKET sock = INVALID_SOCKET;

    sock = GetSocket(argv[1]);

    if (sock == INVALID_SOCKET)
    {
        fprintf(stderr, "Unable to get socket ...\n");
        exit(-1);
    }


    while (TRUE)
    {
        szBuf[0] = '\0';
        wsaBuf.len = MAX_PATH;
        wsaBuf.buf = szBuf;



        nStatus = WSARecv(sock, &wsaBuf, 1, &dwReceived, &dwFlags, (LPWSAOVERLAPPED)NULL, 0);
        if (nStatus == 0)
        {
            if (dwReceived == 0)
            {
                fprintf(stderr, "Client Closed Connection\n");
                break;
            }
            else
            {
                szBuf[dwReceived] = '\0';
                fprintf(stdout, "%s", szBuf);
            }
        }
        else
        {
            fprintf(stderr, "WSARecv failed\n");
            break;
        }
    }


    getchar();

}

