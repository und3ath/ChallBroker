#include "sockduplib.h"


SOCKET GetSocket(char* ParentEventHandle, char* ChildEventHandle, char* Mmaping)
{
	WSAPROTOCOL_INFOW ProtocolInfo;
	SOCKET sockduplicated = INVALID_SOCKET;
	HANDLE ghParentFileMappingEvent = NULL;
	HANDLE ghChildFileMappingEvent = NULL;
	HANDLE ghMMFileMap = NULL;
	DWORD res;

	ghParentFileMappingEvent = (HANDLE)atoi(ParentEventHandle);
	ghChildFileMappingEvent = (HANDLE)atoi(ChildEventHandle);
	ghMMFileMap = (HANDLE)atoi(Mmaping);



	if ((res = WaitForSingleObject(ghParentFileMappingEvent, 5000)) != WAIT_OBJECT_0) {
		if (res == WAIT_TIMEOUT) {
			fprintf(stderr, "Waitforsingleobject() timeout reached!\n");
		}
		else {
			fprintf(stderr, "Waitforsingleobject() failed: %ld\n", GetLastError());
		}
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
		fprintf(stderr, "MapViewOfFile failed: %ld\n", GetLastError());
		return INVALID_SOCKET;
	}

	if (ghMMFileMap != NULL) {
		CloseHandle(ghMMFileMap);
		ghMMFileMap = NULL;
	}

	return sockduplicated;
}




BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
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

