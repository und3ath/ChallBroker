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


	if (!EnableWindowsPrivileges((char*)SE_CREATE_GLOBAL_NAME)) {
		fprintf(stderr, "Unable to adjuste privileges\n");
		exit(-1);
	}


	if (!EnableWindowsPrivileges((char*)SE_DEBUG_NAME)) {
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
	PSID pBatchSID = NULL;
	DWORD dwRes;
	PACL pAclEvent = NULL;
	PSECURITY_DESCRIPTOR pSDEvent = NULL;
	EXPLICIT_ACCESS eaEvent[2];
	SECURITY_ATTRIBUTES saEvent;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld =	SECURITY_WORLD_SID_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;

	// Allocate some specific SID
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pUsersSID)) {
		fprintf(stderr, "AllocateAndInitializeSid() failed: %d\n", GetLastError());
		return false;
	}

	if (!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSID)) {
		fprintf(stderr, "AllocateAndInitializeSid() failed: %d\n", GetLastError());
		return false;
	}

	if (!AllocateAndInitializeSid(&SIDAuthNT, 1, SECURITY_BATCH_RID, 0, 0, 0, 0, 0, 0, 0, &pBatchSID)) {
		fprintf(stderr, "AllocateAndInitializeSid() failed: %d\n", GetLastError());
		return false;
	}


	// Setting DACL for child and parent event
	// user have only synchronize event permission 
	SecureZeroMemory(&eaEvent, 2 * sizeof(EXPLICIT_ACCESS));
	eaEvent[0].grfAccessPermissions = SYNCHRONIZE;
	eaEvent[0].grfAccessMode = SET_ACCESS;
	eaEvent[0].grfInheritance = NO_INHERITANCE;
	eaEvent[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	eaEvent[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	eaEvent[0].Trustee.ptstrName = (LPTSTR)pUsersSID;

	// admin have full acces to the events
	eaEvent[1].grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
	eaEvent[1].grfAccessMode = SET_ACCESS;
	eaEvent[1].grfInheritance = NO_INHERITANCE;
	eaEvent[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	eaEvent[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	eaEvent[1].Trustee.ptstrName = (LPTSTR)pAdminSID;
	
	dwRes = SetEntriesInAcl(2, eaEvent, NULL, &pAclEvent);
	if (dwRes != ERROR_SUCCESS) {
		fprintf(stderr, "SetEntriesInAcl() failed: %d\n", GetLastError());
		return false;
	}

	pSDEvent = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (pSDEvent == NULL) {
		fprintf(stderr, "LocalAlloc() failed: %d\n", GetLastError());
		return false;
	}

	if (!InitializeSecurityDescriptor(pSDEvent, SECURITY_DESCRIPTOR_REVISION)) {
		fprintf(stderr, "InitializeSecurityDescriptor() failed: %d\n", GetLastError());
		return false;
	}

	if (!SetSecurityDescriptorDacl(pSDEvent, TRUE, (PACL)NULL, FALSE)) {
		fprintf(stderr, "SetSecurityDescriptorDacl() failed: %d\n", GetLastError());
		return false;
	}

	
	saEvent.nLength = sizeof(SECURITY_ATTRIBUTES);
	saEvent.lpSecurityDescriptor = pSDEvent;
	// Set the handle inheritable, can be used as is in the child proc
	saEvent.bInheritHandle = TRUE;

	
	// build the events name string and child proc command line
	sprintf_s(szFileMappingObj, MAX_PATH, "%s%i", g_filemapbasename, g_childCount++);
	sprintf_s(szParentEventName, MAX_PATH, "%s%s", szFileMappingObj, "parent");
	sprintf_s(szChildEventName, MAX_PATH, "%s%s", szFileMappingObj, "child");
	


	// Create the parent and child event with appropriate DACL
	if ((ghParentFileMappingEvent = CreateEvent(&saEvent, TRUE, FALSE, szParentEventName)) == NULL) {
		fprintf(stderr, "CreateEvent() failed: %d\n", GetLastError());
		return false;
	}

	if ((ghChildFileMappingEvent = CreateEvent(&saEvent, TRUE, FALSE, szChildEventName)) == NULL) {
		fprintf(stderr, "CreateEvent() failed: %d\n", GetLastError());
		CloseHandle(ghParentFileMappingEvent);
		return false;
	}





	// DACL for the file mapping object
	SECURITY_ATTRIBUTES mapSa;
	EXPLICIT_ACCESS mapEa[2];
	PACL pmapAcl = NULL;
	PSECURITY_DESCRIPTOR mapSD = NULL;
	SecureZeroMemory(&mapEa, 2 * sizeof(EXPLICIT_ACCESS));
	mapEa[0].grfAccessPermissions = FILE_GENERIC_READ;
	mapEa[0].grfAccessMode = SET_ACCESS;
	mapEa[0].grfInheritance = NO_INHERITANCE;
	mapEa[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	mapEa[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	mapEa[0].Trustee.ptstrName = (LPTSTR)pUsersSID;

	// Administrators have full control over the mapped file
	mapEa[1].grfAccessPermissions = FILE_ALL_ACCESS;
	mapEa[1].grfAccessMode = SET_ACCESS;
	mapEa[1].grfInheritance = NO_INHERITANCE;
	mapEa[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	mapEa[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	mapEa[1].Trustee.ptstrName = (LPTSTR)pAdminSID;


	dwRes = SetEntriesInAcl(2, mapEa, NULL, &pmapAcl);
	if (dwRes != ERROR_SUCCESS) {
		fprintf(stderr, "SetEntriesInAcl() failed: %d\n", GetLastError());
		return false;
	}

	mapSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (mapSD == NULL) {
		fprintf(stderr, "LocalAlloc() failed: %d\n", GetLastError());
		return false;
	}

	if (!InitializeSecurityDescriptor(mapSD, SECURITY_DESCRIPTOR_REVISION)) {
		fprintf(stderr, "InitializeSecurityDescriptor() failed: %d\n", GetLastError());
		return false;
	}

	if (!SetSecurityDescriptorDacl(mapSD, TRUE, (PACL)NULL, FALSE)) {
		fprintf(stderr, "SetSecurityDescriptorDacl() failed: %d\n", GetLastError());
		return false;
	}

	mapSa.nLength = sizeof(SECURITY_ATTRIBUTES);
	mapSa.lpSecurityDescriptor = mapSD;
	mapSa.bInheritHandle = TRUE;   // set the flag to inherit handle in child processs 

	ghMMFileMap = CreateFileMapping(INVALID_HANDLE_VALUE, &mapSa, PAGE_READWRITE, 0, sizeof(WSAPROTOCOL_INFOW), szFileMappingObj);




	// build the cmd line
	sprintf_s(szChildComandLineBuf, MAX_PATH, "%s %d %d %d", chall->path, (int)ghParentFileMappingEvent, (int)ghChildFileMappingEvent, (int)ghMMFileMap);


	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	

	HANDLE hUserToken;
	// Logon the user and get his primary token
	if (!LogonUser(chall->user, ".", chall->pass, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &hUserToken)) {
		fprintf(stderr, "LogonUser() failed: %d\n", GetLastError());
		return false;
	}

	
	// Create the DACL for the child process
	SECURITY_ATTRIBUTES procSa;
	EXPLICIT_ACCESS procEa[2];
	PACL pProcAcl = NULL;
	PSECURITY_DESCRIPTOR procSD = NULL;
	SecureZeroMemory(&procEa, 2 * sizeof(EXPLICIT_ACCESS));
	procEa[0].grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
	procEa[0].grfAccessMode = SET_ACCESS;
	procEa[0].grfInheritance = NO_INHERITANCE;
	procEa[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	procEa[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	procEa[0].Trustee.ptstrName = (LPTSTR)pUsersSID;

	// Administrators have full control over the child process
	procEa[1].grfAccessPermissions = PROCESS_ALL_ACCESS;
	procEa[1].grfAccessMode = SET_ACCESS;
	procEa[1].grfInheritance = NO_INHERITANCE;
	procEa[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	procEa[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	procEa[1].Trustee.ptstrName = (LPTSTR)pAdminSID;

	dwRes = SetEntriesInAcl(2, procEa, NULL, &pProcAcl);
	if (dwRes != ERROR_SUCCESS) {
		fprintf(stderr, "SetEntriesInAcl() failed: %d\n", GetLastError());
		return false;
	}
	
	procSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (procSD == NULL) {
		fprintf(stderr, "LocalAlloc() failed: %d\n", GetLastError());
		return false;
	}

	if (!InitializeSecurityDescriptor(procSD, SECURITY_DESCRIPTOR_REVISION)) {
		fprintf(stderr, "InitializeSecurityDescriptor() failed: %d\n", GetLastError());
		return false;
	}

	if (!SetSecurityDescriptorDacl(procSD, TRUE, (PACL)NULL, FALSE)) {
		fprintf(stderr, "SetSecurityDescriptorDacl() failed: %d\n", GetLastError());
		return false;
	}

	procSa.nLength = sizeof(SECURITY_ATTRIBUTES);
	procSa.lpSecurityDescriptor = procSD;
	procSa.bInheritHandle = TRUE;


	// Creat an environment block for the child process
	LPVOID env = NULL;
	if (!CreateEnvironmentBlock(&env, hUserToken, TRUE)) {
		fprintf(stderr, "CreateEnvironmentBlock() failed: %d\n", GetLastError());
		return false;
	}







	// Start the child process 
	// todo the startup path
	if(CreateProcessAsUser(hUserToken, 0, szChildComandLineBuf, &procSa, 0, TRUE, NULL, NULL, "C:\\Users\\ch99", &si, &pi))
	{
		WSAPROTOCOL_INFOW protocoleInfo;
		int nerror;
		LPVOID lpView;


		if (WSADuplicateSocketW(client, pi.dwProcessId, &protocoleInfo) == SOCKET_ERROR) {
			fprintf(stderr, "WSADuplicateSocketW() failed: %d\n", WSAGetLastError());
			return false;
		}

		lpView = MapViewOfFile(ghMMFileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
		if (lpView != NULL)
		{
			memcpy(lpView, &protocoleInfo, sizeof(WSAPROTOCOL_INFOW));
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
			
		CloseHandle(ghMMFileMap);
		ghMMFileMap = NULL;

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

	}
	else
	{
		DisplayError((LPSTR)"CreateProcessWithLogonW");
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