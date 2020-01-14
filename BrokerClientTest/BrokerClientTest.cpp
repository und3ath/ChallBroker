#include <iostream>
#include <WinSock2.h>



FILE* fp;

// #include "../sockduplib/sockduplib.h"
SOCKET GetSocket(char* szFileMapObj, char* ParentEventHandle, char* ChildEventHandle);

SOCKET GetSocket(char* szFileMapObj, char* ParentEventHandle, char* ChildEventHandle)
{
    WSAPROTOCOL_INFOW ProtocolInfo;
    SOCKET sockduplicated = INVALID_SOCKET;
    //char szParentEventName[MAX_PATH] = { 0 };
    //char szChildEventName[MAX_PATH] = { 0 };
    HANDLE ghParentFileMappingEvent = NULL;
    HANDLE ghChildFileMappingEvent = NULL;
    HANDLE ghMMFileMap = NULL;


    ghParentFileMappingEvent = (HANDLE)atoi(ParentEventHandle);
    ghChildFileMappingEvent = (HANDLE)atoi(ChildEventHandle);

    fprintf(fp, "parent: %d\n", ghParentFileMappingEvent);
    fprintf(fp, "child: %d\n", ghChildFileMappingEvent);

    //sprintf_s(szParentEventName, MAX_PATH, "%s%s", szFileMapObj, "parent");
    //sprintf_s(szChildEventName, MAX_PATH, "%s%s", szFileMapObj, "child");

    /*if ((ghParentFileMappingEvent = OpenEventA(SYNCHRONIZE, FALSE, szParentEventName)) == 0)
    {
        fprintf(stderr, "OpenParentEvent failed");
        return INVALID_SOCKET;
    }

    if ((ghChildFileMappingEvent = OpenEventA(SYNCHRONIZE, FALSE, szChildEventName)) == 0) {
        fprintf(stderr, "OpenChildEvent failed\n");
        CloseHandle(ghParentFileMappingEvent);
        ghParentFileMappingEvent = NULL;
        return INVALID_SOCKET;
    }
    */

    if (WaitForSingleObject(ghParentFileMappingEvent, 20000) == WAIT_FAILED) {
        fprintf(fp, "Waitforsingleobject failed: %d\n", GetLastError());
        return INVALID_SOCKET;
    }

    ghMMFileMap = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, szFileMapObj);
    if (ghMMFileMap != NULL) {
        LPVOID lpView = MapViewOfFile(ghMMFileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if ((BYTE*)lpView != NULL) {
            int nStructLen = sizeof(WSAPROTOCOL_INFOW);
            memcpy(&ProtocolInfo, lpView, nStructLen);
            UnmapViewOfFile(lpView);


            sockduplicated = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &ProtocolInfo, 0, 0);
            SetEvent(ghChildFileMappingEvent);

        }
        else
        {
            fprintf(fp, "MapViewOfFile failed: %d\n", GetLastError());
            return INVALID_SOCKET;
        }
    }
    else
    {
        fprintf(fp, "CreateFileMapping failed: %d\n", GetLastError());
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

    while (TRUE)
    {
        szBuf[0] = '\0';
        wsaBuf.len = MAX_PATH;
        wsaBuf.buf = szBuf;

        
        //send(sock, buff, 10, 0);

        nStatus = WSARecv(sock, &wsaBuf, 1, &dwReceived, &dwFlags, (LPWSAOVERLAPPED)NULL, 0);
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

