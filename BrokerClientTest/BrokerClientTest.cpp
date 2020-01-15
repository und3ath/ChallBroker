#include <iostream>
#include <WinSock2.h>



FILE* fp;

// #include "../sockduplib/sockduplib.h"
SOCKET GetSocket(char* ParentEventHandle, char* ChildEventHandle, char* Mmaping);

SOCKET GetSocket(char* ParentEventHandle, char* ChildEventHandle, char* Mmaping)
{
    WSAPROTOCOL_INFOW ProtocolInfo;
    SOCKET sockduplicated = INVALID_SOCKET;
    HANDLE ghParentFileMappingEvent = NULL;
    HANDLE ghChildFileMappingEvent = NULL;
    HANDLE ghMMFileMap = NULL;


    ghParentFileMappingEvent = (HANDLE)atoi(ParentEventHandle);
    ghChildFileMappingEvent = (HANDLE)atoi(ChildEventHandle);
    ghMMFileMap = (HANDLE)atoi(Mmaping);



    if (WaitForSingleObject(ghParentFileMappingEvent, 20000) == WAIT_FAILED) {
        fprintf(stderr, "Waitforsingleobject failed\n");
        return INVALID_SOCKET;
    }


    LPVOID lpView = MapViewOfFile(ghMMFileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if ((BYTE*)lpView != NULL) {
        int nStructLen = sizeof(WSAPROTOCOL_INFOW);
        memcpy(&ProtocolInfo, lpView, nStructLen);
        UnmapViewOfFile(lpView);


        sockduplicated = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &ProtocolInfo, 0, 0);
        SetEvent(ghChildFileMappingEvent);

    }
    else {
        fprintf(stderr, "MapViewOfFile failed: %d\n", GetLastError());
        return INVALID_SOCKET;
    }

    if (ghMMFileMap != NULL) {
        CloseHandle(ghMMFileMap);
        ghMMFileMap = NULL;
    }

    return sockduplicated;
}







int main(int argc, char** argv)
{
    char szBuf[MAX_PATH + 1];
    WSABUF wsaBuf;
    DWORD dwReceived = 0;
    DWORD dwFlags = 0;
    int nStatus;
    WSADATA wsadata;
    SOCKET sock = INVALID_SOCKET;
    int res = fopen_s(&fp, "client.log", "w");

    if (argc < 3) {
        fprintf(stderr, "to few arguments : program filemaping handle handle");
        return -1;
    }

    if ((nStatus = WSAStartup(0x202, &wsadata)) != 0) {
        fprintf(stderr, "Winsock2 Initialisation failed: %d\n", nStatus);
        WSACleanup();
        exit(-1);
    }

    // Use the library to get the socket
    sock = GetSocket(argv[1], argv[2], argv[3]);
    if (sock == INVALID_SOCKET) {
        fprintf(fp, "Unable to get socket ... %s\n", argv[1]);
        exit(-1);
    }



    const char* helloclient = "Hello !\n";
    send(sock, helloclient, strlen(helloclient), 0);

    while (TRUE)
    {
        szBuf[0] = '\0';
        wsaBuf.len = MAX_PATH;
        wsaBuf.buf = szBuf;

        
        //send(sock, buff, 10, 0);

        //nStatus = WSARecv(sock, &wsaBuf, MAX_PATH, &dwReceived, &dwFlags, (LPWSAOVERLAPPED)NULL, 0);
        recv(sock, szBuf, MAX_PATH, 0);
        if (nStatus == 0)
        {
            if (dwReceived == 0)
            {
                fprintf(fp, "Client Closed Connection\n");
                break;
            }
            else
            {
                szBuf[dwReceived] = '\0';
                send(sock, szBuf, dwReceived, 0);
            }
        }
        else
        {
            fprintf(fp, "WSARecv failed\n");
            break;
        }
    }
    fclose(fp);
   
   

}

