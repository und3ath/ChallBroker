#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <WSPiApi.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <UserEnv.h>
#include <aclapi.h>

#include "tinyxml2.h"
using namespace tinyxml2;

#include <list>
#include <thread>
#include <ctime>


char g_listenIP[]= "127.0.0.1";


typedef struct challenge {
	char path[MAX_PATH];
	char user[MAX_PATH];
	char pass[MAX_PATH];
	char port[20];
} challenge_t;



// global vars
tinyxml2::XMLDocument g_xmlConf;
const char* g_xmlconfigfile = "challbroker.xml";
std::list<challenge_t*> g_challenges;
const char g_filemapbasename[] = "Global\\WSADuplicateSocket";
int g_childCount;

// methods def
bool ReadConfig();
void StartChallenge();
void ChallengeBrokerThread(challenge_t* chall);
bool DispatchClient(SOCKET client, challenge_t* chall);
void DisplayError(LPSTR pszAPI);
bool EnableWindowsPrivileges(char* Privilege);
bool GetAccountSidFromUsername(char* username, PSID Sid, DWORD SidSize);
bool CreateNullDacl(PSECURITY_ATTRIBUTES sa);



int main(int argc, char** argv)
{
	int nStatus;
	errno_t err;
	WSADATA wsadata;
	time_t rawtime = time(0);
	struct tm timeinfo;
	FILE* fErrStream;
	FILE* fOperStream;

	char szErrorLogFile[MAX_PATH] = { 0 };
	char szOperLogFile[MAX_PATH] = { 0 };
	char szTimeBuf[MAX_PATH] = { 0 };


	//log files (redirect stderr and stdout to timestamped files)
	/*
	localtime_s(&timeinfo, &rawtime);
	strftime(szTimeBuf, MAX_PATH, "%d%m%Y-%H%M%S", &timeinfo);	
	sprintf_s(szErrorLogFile, MAX_PATH, "%s_%s%s", "error", szTimeBuf, ".log");
	sprintf_s(szOperLogFile, MAX_PATH, "%s_%s%s", "operations", szTimeBuf, ".log");
	
	err = freopen_s(&fErrStream, szErrorLogFile, "w", stderr);
	
	if (err != 0) {
		fprintf(stderr, "freopen_s() failed: %d\n", err);
		exit(-1);
	}

	err = freopen_s(&fOperStream, szOperLogFile, "w", stdout);
	if (err != 0) {
		fprintf(stderr, "freopen_s() failed: %d\n", err);
		exit(-1);
	}

	*/
	if (!EnableWindowsPrivileges((char*)SE_CREATE_GLOBAL_NAME)) {
		fprintf(stderr, "Unable to adjuste privileges\n");
		exit(-1);
	}


	// Load the configuration file; 
	if (g_xmlConf.LoadFile(g_xmlconfigfile) != XML_SUCCESS) {
		fprintf(stderr, "Failed to open xml config : %s\n", g_xmlconfigfile);
		exit(-1);
	}


    // Initialize winsock dll. 
	if ((nStatus = WSAStartup(0x202, &wsadata)) != 0) {
		fprintf(stderr, "Winsock2 Initialisation failed: %d\n", nStatus);
		WSACleanup();
		exit(-1);
	}


	if (ReadConfig()) {
		StartChallenge();
	}

	

	return 0;
}



bool EnableWindowsPrivileges(char* Privilege)
{
	LUID luid = {};
	TOKEN_PRIVILEGES tp;
	HANDLE hprocess = GetCurrentProcess();
	HANDLE htoken = {};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) {
		return false;
	}

	if (!OpenProcessToken(hprocess, TOKEN_ALL_ACCESS, &htoken)) {
		return false;
	}

	if (!AdjustTokenPrivileges(htoken, FALSE, &tp, sizeof(PTOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		return false;
	}

	return true;
}



void DisplayError(LPSTR pszAPI)
{
	LPVOID lpvMessageBuffer;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&lpvMessageBuffer, 0, NULL);
	fprintf(stderr, "ERROR: API        = %s.\n", pszAPI);
	fprintf(stderr, "       error code = %d.\n", GetLastError());
	fprintf(stderr, "       message    = %s.\n", (LPSTR)lpvMessageBuffer);
	LocalFree(lpvMessageBuffer);
}


bool ReadConfig()
{	
	XMLNode* root = g_xmlConf.FirstChildElement("challenges");
	if (root == nullptr) {
		fprintf(stderr, "Parsing xml failed \n");
		return false;
	}

	
	XMLNode * node = root->FirstChildElement();
	while (node) {

		challenge_t *chall = NULL;
		chall = (challenge_t*)malloc(sizeof(challenge_t));
		if (chall == NULL) {
			fprintf(stderr, "malloc() failed\n");
			return false;
		}


		strcpy_s(chall->path, MAX_PATH, node->FirstChildElement("path")->GetText());
		strcpy_s(chall->user, MAX_PATH, node->FirstChildElement("user")->GetText());
		strcpy_s(chall->pass, MAX_PATH, node->FirstChildElement("pass")->GetText());
		strcpy_s(chall->port, 20,  node->FirstChildElement("port")->GetText());
		
		g_challenges.push_back(chall);

		node = node->NextSiblingElement();
	}

	return true;
}


void StartChallenge()
{
	for (auto const& i : g_challenges) {
		fprintf(stdout, "%s\n", i->path);
		fprintf(stdout, "%s\n", i->user);
		fprintf(stdout, "%s\n", i->pass);
		fprintf(stdout, "%s\n", i->port);
		

		std::thread th(ChallengeBrokerThread, i);
		th.join();
	}
}




// Listening thread for handling clients
void ChallengeBrokerThread(challenge_t* chall)
{
	SOCKADDR_STORAGE saFrom;
	int nFromLen;
	int i;
	SOCKET listensock = INVALID_SOCKET;
	SOCKET acceptsock = INVALID_SOCKET;


	struct addrinfo hints;
	struct addrinfo* res;
	struct addrinfo* pAddr;




	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;


	

	if (getaddrinfo(g_listenIP, chall->port, &hints, &res) != NO_ERROR) {
		fprintf(stderr, "getaddrinfo failed. Error: %d\n", WSAGetLastError());
		return;
	}

	for (pAddr = res, i = 1; pAddr != NULL; pAddr = pAddr->ai_next, i++) {
		listensock = WSASocketW(pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol, NULL, 0, 0);
		if (listensock != INVALID_SOCKET) {
			break;
		}
	}

	if (pAddr == NULL) {
		fprintf(stderr, "unable to find suitable socket.\n");
		return;
	}
	
	listensock = WSASocketW(pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED);

	if (listensock == INVALID_SOCKET) {
		fprintf(stderr, "WSASocketW() failed. Error: %d\n", WSAGetLastError());
		return;
	}


	if (bind(listensock, (struct sockaddr*)pAddr->ai_addr, pAddr->ai_addrlen) == SOCKET_ERROR) {
		fprintf(stderr, "bind() failed. Error: %d\n", WSAGetLastError());
		return;
	}


	if (listen(listensock, 5) == SOCKET_ERROR) {
		fprintf(stderr, "listen() failed. Error: %d\n", WSAGetLastError());
		return;
	}

	nFromLen = sizeof(saFrom);
	while (true)
	{
		fprintf(stdout, "Waiting for client.\n");
		acceptsock = WSAAccept(listensock, (struct sockaddr*)&saFrom, &nFromLen, NULL, 0);
		if (acceptsock == INVALID_SOCKET) {
			fprintf(stderr, "WSAAccept failed. Error: %d\n", WSAGetLastError());
			break;
		}

		

		DispatchClient(acceptsock, chall);


	}


	
}



bool GetAccountSidFromUsername(char* username, PSID Sid, DWORD SidSize)
{
	SID_NAME_USE snu;
	DWORD cbSid = SidSize, cchRD = 0;
	LPCSTR rd = NULL;
	bool succ = LookupAccountName(NULL, username, Sid, &cbSid, (LPSTR)rd, &cchRD, &snu);
	if (!succ)
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return false;

		rd = (LPCSTR)LocalAlloc(LPTR, cchRD * sizeof(*rd));
		if (!rd)
		{
			SetLastError(ERROR_OUTOFMEMORY);
			return false;
		}
		cbSid = SidSize;
		succ = LookupAccountName(NULL, username, Sid, &cbSid, (LPSTR)rd, &cchRD, &snu);
	}
	return succ;
}




bool CreateNullDacl(PSECURITY_ATTRIBUTES sa) {
	PSECURITY_DESCRIPTOR pSD;
	if (sa == NULL) {
		return false;
	}
	pSD = (PSECURITY_ATTRIBUTES)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (pSD == NULL) {
		fprintf(stderr, "LocalAlloc() failed: %d\n", GetLastError());
		return false;
	}

	if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
		return false;
	}

	if (!SetSecurityDescriptorDacl(pSD, TRUE, (PACL)NULL, FALSE)) {
		return true;
	}


	sa->nLength = sizeof(SECURITY_ATTRIBUTES);
	sa->lpSecurityDescriptor = pSD;
	sa->bInheritHandle = TRUE;
	return true;
}



// Dispath clients, logon user, and spawn subprocess. 
bool DispatchClient(SOCKET client, challenge_t* chall) {
	char szFileMappingObj[MAX_PATH] = { 0 };
	char szParentEventName[MAX_PATH] = { 0 };
	char szChildEventName[MAX_PATH] = { 0 };
	char szChildComandLineBuf[MAX_PATH] = { 0 };

	HANDLE ghParentFileMappingEvent = NULL;
	HANDLE ghChildFileMappingEvent = NULL;
	HANDLE ghMMFileMap = NULL;



	/*byte sidbuf[SECURITY_MAX_SID_SIZE];
	PSID challusersid = (PSID)sidbuf;
	if (!GetAccountSidFromUsername(chall->user, challusersid, sizeof(sidbuf))) {
		fprintf(stderr, "GetAccountSidFromUsername() failed: %d\n", GetLastError());
		return false;
	}*/
	PSID pUsersSID = NULL;
	PSID pAdminSID = NULL;
	DWORD dwRes;
	PACL pAcl = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&SIDAuthNT, 1, SECURITY_AUTHENTICATED_USER_RID,0, 0, 0, 0, 0, 0, 0, &pUsersSID)) {
		fprintf(stderr, "AllocateAndInitializeSid() failed: %d\n", GetLastError());
		return false;
	}

	if (!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSID)) {
		fprintf(stderr, "AllocateAndInitializeSid() failed: %d\n", GetLastError());
		return false;
	}

	EXPLICIT_ACCESS ea[2];
	SecureZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
	ea[0].grfAccessPermissions = EVENT_ALL_ACCESS;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
	ea[0].Trustee.ptstrName = (LPTSTR)pUsersSID;


	ea[1].grfAccessPermissions = EVENT_ALL_ACCESS;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName = (LPTSTR)pAdminSID;



	dwRes = SetEntriesInAcl(2, ea, NULL, &pAcl);
	if (dwRes != ERROR_SUCCESS) {
		fprintf(stderr, "SetEntriesInAcl() failed: %d\n", GetLastError());
		return false;
	}

	PSECURITY_DESCRIPTOR pSD = NULL;
	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (pSD == NULL) {
		fprintf(stderr, "LocalAlloc() failed: %d\n", GetLastError());
		return false;
	}

	if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
		fprintf(stderr, "InitializeSecurityDescriptor() failed: %d\n", GetLastError());
		return false;
	}


	if (!SetSecurityDescriptorDacl(pSD, TRUE, pAcl, FALSE)) { 
		fprintf(stderr, "SetSecurityDescriptorDacl() failed: %d\n", GetLastError());
		return false;
	}

	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = pSD;
	sa.bInheritHandle = TRUE;



	sprintf_s(szFileMappingObj, MAX_PATH, "%s%i", g_filemapbasename, g_childCount++);
	sprintf_s(szParentEventName, MAX_PATH, "%s%s", szFileMappingObj, "parent");
	sprintf_s(szChildEventName, MAX_PATH, "%s%s", szFileMappingObj, "child");
	sprintf_s(szChildComandLineBuf, MAX_PATH, "%s %s", chall->path, szFileMappingObj);





	if ((ghParentFileMappingEvent = CreateEvent(&sa, TRUE, FALSE, szParentEventName)) == NULL) {
		fprintf(stderr, "CreateEvent() failed: %d\n", GetLastError());
		return false;
	}

	if ((ghChildFileMappingEvent = CreateEvent(&sa, TRUE, FALSE, szChildEventName)) == NULL) {
		fprintf(stderr, "CreateEvent() failed: %d\n", GetLastError());
		CloseHandle(ghParentFileMappingEvent);
		return false;
	}





	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	SECURITY_ATTRIBUTES procSa;
	CreateNullDacl(&procSa);

	HANDLE htok;
	if (!LogonUser(chall->user, ".", chall->pass, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &htok)) {
		fprintf(stderr, "LogonUser() failed: %d\n", GetLastError());
		return false;

	}





	// todo the startup path
	if(CreateProcessAsUser(htok, 0, szChildComandLineBuf, &procSa, 0, FALSE, NULL, NULL, "C:\\Users\\ch99", &si, &pi))
	{
		WSAPROTOCOL_INFOW protocoleInfo;
		int nerror;
		LPVOID lpView;
		int nStructLen = sizeof(WSAPROTOCOL_INFOW);


		if (WSADuplicateSocketW(client, pi.dwProcessId, &protocoleInfo) == SOCKET_ERROR) {
			fprintf(stderr, "WSADuplicateSocketW() failed: %d\n", WSAGetLastError());
			return false;
		}


		ghMMFileMap = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, nStructLen, szFileMappingObj);
		if (ghMMFileMap != NULL)
		{
			if ((nerror = GetLastError()) == ERROR_ALREADY_EXISTS)
			{
				fprintf(stderr, "CreateFileMapping() failed: mapping already exists\n");
				return false;
			}
			else
			{
				lpView = MapViewOfFile(ghMMFileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
				if (lpView != NULL)
				{
					memcpy(lpView, &protocoleInfo, nStructLen);
					UnmapViewOfFile(lpView);

					SetEvent(ghParentFileMappingEvent);
					if (WaitForSingleObject(ghChildFileMappingEvent, 20000) == WAIT_OBJECT_0)
					{
						fprintf(stderr, "WaitForSingleObject() object failed: %d\n", GetLastError());
						return false;
					}
				}
				else
				{
					fprintf(stderr, "MapViewOfFile() failed: %d\n", GetLastError());
					
				}
			}
			CloseHandle(ghMMFileMap);
			ghMMFileMap = NULL;
		}
		else
		{
			fprintf(stderr, "CreateFileMapping() failed: %d\n", GetLastError());

		}

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

	}
	else
	{
		DisplayError((LPSTR)"CreateProcessWithLogonW");
		//fprintf(stderr, "CreateProcessWithLogonW() failed: %d", GetLastError());
		return false;
	}



	if (ghParentFileMappingEvent != NULL) {
		CloseHandle(ghParentFileMappingEvent);
		ghParentFileMappingEvent = NULL;
	}

	if (ghChildFileMappingEvent != NULL) {
		CloseHandle(ghChildFileMappingEvent);
		ghChildFileMappingEvent = NULL;
	}

	return true;

}