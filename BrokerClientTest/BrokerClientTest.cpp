#include <iostream>
#include <WinSock2.h>
#include "sockduplib.h"

FILE* g_fp;

int main(int argc, char** argv)
{
    char szBuf[MAX_PATH + 1];
    WSABUF wsaBuf;
    DWORD dwReceived = 0;
    DWORD dwFlags = 0;
    int nStatus;
    WSADATA wsadata;
    SOCKET sock = INVALID_SOCKET;
    errno_t res = fopen_s(&g_fp, "client.log", "w");
    if (res != 0) {
        fprintf(stderr, "fopen_s() failed: %d\n", GetLastError());
        exit(-1);
    }

    if (argc < 3) {
        fprintf(g_fp, "to few arguments : program.exe handle handle handle");
        return -1;
    }

    if ((nStatus = WSAStartup(0x202, &wsadata)) != 0) {
        fprintf(g_fp, "Winsock2 Initialization failed: %d\n", nStatus);
        WSACleanup();
        exit(-1);
    }

    // Use the library to get the socket( you need to initialize WSADATA yourself )
    GetSocket(&sock, argv[1], argv[2], argv[3]);
    if (sock == INVALID_SOCKET) {
        fprintf(g_fp, "Unable to get socket \n");
        exit(-1);
    }

    const char* helloclient = "Hello !\n";
    send(sock, helloclient, strlen(helloclient), 0);

    while (TRUE) {
        szBuf[0] = '\0';
        wsaBuf.len = MAX_PATH;
        wsaBuf.buf = szBuf;

        recv(sock, szBuf, MAX_PATH, 0);
        if (nStatus == 0) {
            if (dwReceived == 0) {
                fprintf(g_fp, "Client Closed Connection\n");
                break;
            }
            else {
                szBuf[dwReceived] = '\0';
                send(sock, szBuf, dwReceived, 0);
            }
        }
        else {
            fprintf(g_fp, "WSARecv failed\n");
            break;
        }
    }
    fclose(g_fp);
   
}

