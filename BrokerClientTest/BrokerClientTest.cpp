#include <iostream>
#include <WinSock2.h>

// #include "../sockduplib/sockduplib.h"

FILE* fp;


SOCKET GetSocket(char* szFileMapObj);

SOCKET GetSocket(char* szFileMapObj)
{
    WSAPROTOCOL_INFOW ProtocolInfo;
    SOCKET sockduplicated = INVALID_SOCKET;
    char szParentEventName[MAX_PATH] = { 0 };
    char szChildEventName[MAX_PATH] = { 0 };
    HANDLE ghParentFileMappingEvent = NULL;
    HANDLE ghChildFileMappingEvent = NULL;
    HANDLE ghMMFileMap = NULL;

    

    sprintf_s(szParentEventName, MAX_PATH, "%s%s", szFileMapObj, "parent");
    sprintf_s(szChildEventName, MAX_PATH, "%s%s", szFileMapObj, "child");

    //if ((ghParentFileMappingEvent = OpenEventA(SYNCHRONIZE, FALSE, szParentEventName)) == 0)
    if ((ghParentFileMappingEvent = CreateEventExA(NULL, szParentEventName, 0, SYNCHRONIZE)) == 0)
    {
        fprintf(fp, "OpenParentEvent failed: %d\n", GetLastError());
        return INVALID_SOCKET;
    }

    if ((ghChildFileMappingEvent = OpenEventA(SYNCHRONIZE, FALSE, szChildEventName)) == 0) {
        fprintf(fp, "OpenChildEvent failed: %d\n", GetLastError());
        CloseHandle(ghParentFileMappingEvent);
        ghParentFileMappingEvent = NULL;
        return INVALID_SOCKET;
    }


    if (WaitForSingleObject(ghParentFileMappingEvent, 20000) == WAIT_FAILED)
    {
        fprintf(fp, "Waitforsingleobject failed\n");
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
            fprintf(fp, "MapViewOfFile failed\n");
            return INVALID_SOCKET;
        }
    }
    else
    {
        fprintf(fp, "CreateFileMapping failed\n");
        return INVALID_SOCKET;
    }

    if (ghChildFileMappingEvent != NULL) {
        CloseHandle(ghChildFileMappingEvent);
        ghChildFileMappingEvent = NULL;
    }

    if (ghParentFileMappingEvent != NULL) {
        CloseHandle(ghParentFileMappingEvent);
        ghParentFileMappingEvent = NULL;
    }

    if (ghMMFileMap != NULL) {
        CloseHandle(ghMMFileMap);
        ghMMFileMap = NULL;
    }
    //fclose(fp);
    return sockduplicated;
}




int main(int argc, char** argv)
{
    char szBuf[MAX_PATH + 1];
    WSABUF wsaBuf;
    DWORD dwReceived = 0;
    DWORD dwFlags = 0;
    int nStatus;

    SOCKET sock = INVALID_SOCKET;
    int res = fopen_s(&fp, "client.log", "w");
    sock = GetSocket(argv[1]);

    



    if (sock == INVALID_SOCKET)
    {
        fprintf(fp, "Unable to get socket ... %s\n", argv[1]);
        exit(-1);
    }

    char buff[10] = "salut\n";

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

