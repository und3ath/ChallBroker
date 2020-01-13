// dllmain.cpp : Définit le point d'entrée de l'application DLL.
#include "sockduplib.h"


SOCKET GetSocket(char* szFileMapObj)
{
    WSAPROTOCOL_INFOW ProtocolInfo;
    SOCKET sockduplicated = INVALID_SOCKET;
    char szParentEventName[MAX_PATH] = { 0 };
    char szChildEventName[MAX_PATH] = { 0 };
    HANDLE ghParentFileMappingEvent = NULL;
    HANDLE ghChildFileMappingEvent = NULL;
    HANDLE ghMMFileMap = NULL;

    FILE* fp;
    int ret = fopen_s(&fp, "loggg.txt", "w");

    sprintf_s(szParentEventName, MAX_PATH, "%s%s", szFileMapObj, "parent");
    sprintf_s(szChildEventName, MAX_PATH, "%s%s", szFileMapObj, "child");

    if ((ghParentFileMappingEvent = OpenEventA(SYNCHRONIZE, FALSE, szParentEventName)) == 0)
    {
        fprintf(fp, "OpenParentEvent failed");
        return INVALID_SOCKET;
    }

    if ((ghChildFileMappingEvent = OpenEventA(SYNCHRONIZE, FALSE, szChildEventName)) == 0) {
        fprintf(fp, "OpenChildEvent failed\n");
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
    fclose(fp);
    return sockduplicated;
}





BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

