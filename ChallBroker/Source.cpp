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
#include <vector>
#include <ctime>
#include <future>
#include <chrono>


char g_listenIP[]= "127.0.0.1";


typedef struct challenge {
	char path[MAX_PATH];
	char user[MAX_PATH];
	char pass[MAX_PATH];
	char port[20];
	PHANDLE stopEvent;
} challenge_t;



// global vars
FILE* g_logFile;
tinyxml2::XMLDocument g_xmlConf;
const char* g_xmlconfigfile = "C:\\ProgramData\\ChallBroker\\challbroker.xml";
std::list<challenge_t*> g_challenges;
std::vector<std::thread> g_threadsVector;
PSID g_pBrokerSID;
PSID g_pAdministratorsSID;
SID_IDENTIFIER_AUTHORITY g_SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
SID_IDENTIFIER_AUTHORITY g_SIDAuthNT = SECURITY_NT_AUTHORITY;



// methods def
bool ReadConfig();
void StartChallenge();
void ChallengeBrokerThread(challenge_t* chall);
bool DispatchClient(SOCKET client, challenge_t* chall);
bool GetAccountSidFromUsername(char* username, PSID Sid, DWORD SidSize);



// service specific
SERVICE_STATUS g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;
HANDLE g_StopEvent = INVALID_HANDLE_VALUE;
void WINAPI ServiceMain(DWORD argc, LPTSTR* arvg);
void WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);
const char* g_serviceName = "Challenges Broker";

std::promise<void> exitSignal;





int main(int argc, char** argv)
{

	errno_t err;
	if ((err = fopen_s(&g_logFile, "C:\\ProgramData\\ChallBroker\\challbroker-error.log", "a+")) != 0) {
		fprintf(stderr, "fopen_s() failed: %d\n", err);
		exit(-1);
	}





	SERVICE_TABLE_ENTRY ServiceTable[] = { {(LPSTR)g_serviceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain}, {nullptr, nullptr} };




	if (StartServiceCtrlDispatcher(ServiceTable) == false) {
		fprintf(g_logFile, "StartServiceCtrlDispatcher() failed: %d\n", GetLastError());
		return -1;
	}







	/*int nStatus;
	WSADATA wsadata;
	errno_t err;

	if((err = fopen_s(&g_logFile, "challbroker-error.log", "a+")) != 0) {
		fprintf(stderr, "fopen_s() faailed: %d\n", err);
		exit(-1);
	}
	
	// Load the configuration file; 
	if (g_xmlConf.LoadFile(g_xmlconfigfile) != XML_SUCCESS) {
		fprintf(g_logFile, "Failed to open xml config : %s\n", g_xmlconfigfile);
		exit(-1);
	}
	
	g_pBrokerSID = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
	if (!GetAccountSidFromUsername((char*)"broker", g_pBrokerSID, SECURITY_MAX_SID_SIZE)) {
		fprintf(g_logFile, "GetAccountSidFromUsername() failed: %d\n", GetLastError());
		exit(-1);
	}
	
	if (!AllocateAndInitializeSid(&g_SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &g_pAdministratorsSID)) {
		fprintf(g_logFile, "AllocateAndInitializeSid() failed: %d\n", GetLastError());
		exit(-1);
	}

    // Initialize winsock dll. 
	if ((nStatus = WSAStartup(0x202, &wsadata)) != 0) {
		fprintf(g_logFile, "Winsock2 Initialization failed: %d\n", nStatus);
		WSACleanup();
		exit(-1);
	}

	if (!ReadConfig()) {
		fprintf(g_logFile, "ReadConfig() failed.\n");
		exit(-1);
	}

	StartChallenge();

	fclose(g_logFile);
	*/
	return 0;
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
	DWORD status = E_FAIL;
	if ((g_StatusHandle = RegisterServiceCtrlHandler(g_serviceName, ServiceCtrlHandler)) == nullptr) {
		fprintf(g_logFile, "RegisterServiceCtrlHandler() failed: %d\n", GetLastError());
		return;
	}


	SecureZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
	g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	g_ServiceStatus.dwControlsAccepted = 0;
	g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwServiceSpecificExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 0;


	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == false) {
		fprintf(g_logFile, "SetServiceStatus() failed: %d\n", GetLastError());
		return;
	}

	g_ServiceStopEvent = CreateEvent(nullptr, true, false, nullptr);
	if (g_ServiceStopEvent == nullptr) {
		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		g_ServiceStatus.dwWin32ExitCode = GetLastError();
		g_ServiceStatus.dwCheckPoint = -1;
		if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == false) {
			fprintf(g_logFile, "SetServiceStatus() failed: %d\n", GetLastError());
		}
		return;
	}

	g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == false) {
		fprintf(g_logFile, "SetServiceStatus() failed: %d\n", GetLastError());
	}

	HANDLE hthread = CreateThread(NULL, 0, ServiceWorkerThread, nullptr, 0, nullptr);
	WaitForSingleObject(hthread, INFINITE);
	CloseHandle(hthread);

	g_ServiceStatus.dwControlsAccepted = 0;
	g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 3;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		fprintf(g_logFile, "SetServiceStatus() failed: %d\n", GetLastError());
	}

}

void WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
	switch (CtrlCode)
	{
	case SERVICE_CONTROL_STOP:

		fprintf(g_logFile, "My Sample Service: ServiceCtrlHandler: SERVICE_CONTROL_STOP Request");

		if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
			break;

		for (auto const& hh : g_challenges) {
			SetEvent(*hh->stopEvent);
		}
		

		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		g_ServiceStatus.dwWin32ExitCode = 0;
		g_ServiceStatus.dwCheckPoint = 4;

		if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
			fprintf(g_logFile, "My Sample Service: ServiceCtrlHandler: SetServiceStatus returned error");
		}

		// This will signal the worker thread to start shutting down
		SetEvent(g_ServiceStopEvent);

		break;

	default:
		break;
	}

	fprintf(g_logFile, "My Sample Service: ServiceCtrlHandler: Exit");
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
	int nStatus;
	WSADATA wsadata;
	errno_t err;



	// Load the configuration file; 
	if (g_xmlConf.LoadFile(g_xmlconfigfile) != XML_SUCCESS) {
		fprintf(g_logFile, "Failed to open xml config : %s\n", g_xmlconfigfile);
		exit(-1);
	}

	g_pBrokerSID = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
	if (!GetAccountSidFromUsername((char*)"broker", g_pBrokerSID, SECURITY_MAX_SID_SIZE)) {
		fprintf(g_logFile, "GetAccountSidFromUsername() failed: %d\n", GetLastError());
		exit(-1);
	}

	if (!AllocateAndInitializeSid(&g_SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &g_pAdministratorsSID)) {
		fprintf(g_logFile, "AllocateAndInitializeSid() failed: %d\n", GetLastError());
		exit(-1);
	}

	// Initialize winsock dll. 
	if ((nStatus = WSAStartup(0x202, &wsadata)) != 0) {
		fprintf(g_logFile, "Winsock2 Initialization failed: %d\n", nStatus);
		WSACleanup();
		exit(-1);
	}

	if (!ReadConfig()) {
		fprintf(g_logFile, "ReadConfig() failed.\n");
		exit(-1);
	}

	StartChallenge();

	fclose(g_logFile);
	return ERROR_SUCCESS;
}


bool ReadConfig()
{	
	XMLNode* root = g_xmlConf.FirstChildElement("challenges");
	if (root == nullptr) {
		fprintf(g_logFile, "Parsing xml failed \n");
		return false;
	}

	
	XMLNode * node = root->FirstChildElement();
	while (node) {

		challenge_t *chall = nullptr;
		chall = (challenge_t*)malloc(sizeof(challenge_t));
		if (chall == nullptr) {
			fprintf(g_logFile, "malloc() failed\n");
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
		HANDLE stopevent = CreateEvent(nullptr, true, false, nullptr);
		i->stopEvent = &stopevent;
		g_threadsVector.emplace_back(std::thread(ChallengeBrokerThread, i));
	}

	// waiting for thread to complete
	for (auto& th : g_threadsVector) {
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

	HANDLE hEvents[2];
	hEvents[0] = CreateEvent(nullptr, FALSE, FALSE, nullptr);
	hEvents[1] = *chall->stopEvent;




	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(g_listenIP, chall->port, &hints, &res) != NO_ERROR) {
		fprintf(g_logFile, "getaddrinfo failed. Error: %d\n", WSAGetLastError());
		return;
	}

	for (pAddr = res, i = 1; pAddr != nullptr; pAddr = pAddr->ai_next, i++) {
		listensock = WSASocketW(pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol, nullptr, 0, 0);
		if (listensock != INVALID_SOCKET) {
			break;
		}
	}

	if (pAddr == nullptr) {
		fprintf(g_logFile, "unable to find suitable socket.\n");
		return;
	}
	
	listensock = WSASocketW(pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
	if (listensock == INVALID_SOCKET) {
		fprintf(g_logFile, "WSASocketW() failed. Error: %d\n", WSAGetLastError());
		return;
	}

	if (bind(listensock, (struct sockaddr*)pAddr->ai_addr, pAddr->ai_addrlen) == SOCKET_ERROR) {
		fprintf(g_logFile, "bind() failed. Error: %d\n", WSAGetLastError());
		return;
	}

	if (listen(listensock, 5) == SOCKET_ERROR) {
		fprintf(g_logFile, "listen() failed. Error: %d\n", WSAGetLastError());
		return;
	}

	nFromLen = sizeof(saFrom);
	while (true) 
	{
		//acceptsock = WSAAccept(listensock, (struct sockaddr*)&saFrom, &nFromLen, nullptr, 0);
		WSAEventSelect(listensock, hEvents[0], FD_ACCEPT);

		if (WaitForMultipleObjects(2, hEvents, FALSE, INFINITE) == WAIT_OBJECT_0) {
			acceptsock = WSAAccept(listensock, (struct sockaddr*) & saFrom, &nFromLen, nullptr, 0);
		}
		else {
			break;
		}


		if (acceptsock == INVALID_SOCKET) {
			fprintf(g_logFile, "WSAAccept failed. Error: %d\n", WSAGetLastError());
			break;
		}

		if (!DispatchClient(acceptsock, chall)) {
			fprintf(g_logFile, "DispatchClient() failed\n");
		}
	}

	//WSAEventSelect(listensock, hEvents[0], 0);
	CloseHandle(hEvents);
}


bool GetAccountSidFromUsername(char* username, PSID Sid, DWORD SidSize)
{
	SID_NAME_USE snu;
	DWORD cbSid = SidSize, cchRD = 0;
	LPCSTR rd = nullptr;
	bool succ = LookupAccountName(nullptr, username, Sid, &cbSid, (LPSTR)rd, &cchRD, &snu);
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
		succ = LookupAccountName(nullptr, username, Sid, &cbSid, (LPSTR)rd, &cchRD, &snu);
	}
	return succ;
}

// dispatch clients, login user, and spawn subprocess. 
bool DispatchClient(SOCKET client, challenge_t* chall) {
	char szChildComandLineBuf[MAX_PATH] = { 0 };
	char szUSerHomeDirectory[MAX_PATH] = { 0 };

	HANDLE ghParentFileMappingEvent = nullptr;
	HANDLE ghChildFileMappingEvent = nullptr;
	HANDLE ghMMFileMap = nullptr;

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };

	PSID pUsersSID = nullptr;
	PSID pChallUserSID = nullptr;

	DWORD dwRes;
	PACL pAclEvent = nullptr;
	PSECURITY_DESCRIPTOR pSDEvent = nullptr;
	EXPLICIT_ACCESS eaEvent[2];
	SECURITY_ATTRIBUTES saEvent;

	HANDLE hUserToken;

	// Allocate some specific SID
	if (!AllocateAndInitializeSid(&g_SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pUsersSID)) {
		fprintf(g_logFile, "AllocateAndInitializeSid() failed: %d\n", GetLastError());
		return false;
	}

	pChallUserSID = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
	if (!GetAccountSidFromUsername(chall->user, pChallUserSID, SECURITY_MAX_SID_SIZE)) {
		fprintf(g_logFile, "GetAccountSidFromUsername() failed: %d\n", GetLastError());
		return false;
	}

	// Setting DACL for child and parent event
	// user have only synchronize event permission 
	SecureZeroMemory(&eaEvent, 1 * sizeof(EXPLICIT_ACCESS));
	// admin have full access to the events
	eaEvent[0].grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
	eaEvent[0].grfAccessMode = SET_ACCESS;
	eaEvent[0].grfInheritance = NO_INHERITANCE;
	eaEvent[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	eaEvent[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	eaEvent[0].Trustee.ptstrName = (LPTSTR)g_pAdministratorsSID;
	
	if((dwRes = SetEntriesInAcl(1, eaEvent, nullptr, &pAclEvent)) != ERROR_SUCCESS) {
		fprintf(g_logFile, "SetEntriesInAcl() failed: %d\n", GetLastError());
		return false;
	}

	if((pSDEvent = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH)) == nullptr) {
		fprintf(g_logFile, "LocalAlloc() failed: %d\n", GetLastError());
		return false;
	}

	if (!InitializeSecurityDescriptor(pSDEvent, SECURITY_DESCRIPTOR_REVISION)) {
		fprintf(g_logFile, "InitializeSecurityDescriptor() failed: %d\n", GetLastError());
		return false;
	}

	if (!SetSecurityDescriptorDacl(pSDEvent, TRUE, pAclEvent, FALSE)) {
		fprintf(g_logFile, "SetSecurityDescriptorDacl() failed: %d\n", GetLastError());
		return false;
	}

	saEvent.nLength = sizeof(SECURITY_ATTRIBUTES);
	saEvent.lpSecurityDescriptor = pSDEvent;
	saEvent.bInheritHandle = TRUE;

	// Create the parent and child event with appropriate DACL
	if ((ghParentFileMappingEvent = CreateEvent(&saEvent, TRUE, FALSE, nullptr)) == nullptr) {
		fprintf(g_logFile, "CreateEvent() failed: %d\n", GetLastError());
		return false;
	}

	if ((ghChildFileMappingEvent = CreateEvent(&saEvent, TRUE, FALSE, nullptr)) == nullptr) {
		fprintf(g_logFile, "CreateEvent() failed: %d\n", GetLastError());
		CloseHandle(ghParentFileMappingEvent);
		return false;
	}

	// DACL for the file mapping object
	SECURITY_ATTRIBUTES mapSa;
	EXPLICIT_ACCESS mapEa[1];
	PACL pmapAcl = nullptr;
	PSECURITY_DESCRIPTOR mapSD = nullptr;
	SecureZeroMemory(&mapEa, 1 * sizeof(EXPLICIT_ACCESS));
	mapEa[0].grfAccessPermissions = FILE_ALL_ACCESS;
	mapEa[0].grfAccessMode = SET_ACCESS;
	mapEa[0].grfInheritance = NO_INHERITANCE;
	mapEa[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	mapEa[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	mapEa[0].Trustee.ptstrName = (LPTSTR)g_pAdministratorsSID;

	if((dwRes = SetEntriesInAcl(1, mapEa, nullptr, &pmapAcl)) != ERROR_SUCCESS) {
		fprintf(g_logFile, "SetEntriesInAcl() failed: %d\n", GetLastError());
		return false;
	}

	if((mapSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH)) == nullptr) {
		fprintf(g_logFile, "LocalAlloc() failed: %d\n", GetLastError());
		return false;
	}

	if (!InitializeSecurityDescriptor(mapSD, SECURITY_DESCRIPTOR_REVISION)) {
		fprintf(g_logFile, "InitializeSecurityDescriptor() failed: %d\n", GetLastError());
		return false;
	}

	if (!SetSecurityDescriptorDacl(mapSD, TRUE, pmapAcl, FALSE)) {
		fprintf(g_logFile, "SetSecurityDescriptorDacl() failed: %d\n", GetLastError());
		return false;
	}

	mapSa.nLength = sizeof(SECURITY_ATTRIBUTES);
	mapSa.lpSecurityDescriptor = mapSD;
	mapSa.bInheritHandle = TRUE;

	if((ghMMFileMap = CreateFileMapping(INVALID_HANDLE_VALUE, &mapSa, PAGE_READWRITE, 0, sizeof(WSAPROTOCOL_INFOW), nullptr)) == nullptr) {
		fprintf(g_logFile, "CreateFileMapping() failed: %d\n", GetLastError());
		return false;
	}

	// build the cmd line
	sprintf_s(szChildComandLineBuf, MAX_PATH, "%s %d %d %d", chall->path, (int)ghParentFileMappingEvent, (int)ghChildFileMappingEvent, (int)ghMMFileMap);
	sprintf_s(szUSerHomeDirectory, MAX_PATH, "%s%s", "c:\\users\\", chall->user);

	// login the user and get his primary token
	if (!LogonUser(chall->user, ".", chall->pass, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &hUserToken)) {
		fprintf(g_logFile, "LogonUser() failed: %d\n", GetLastError());
		return false;
	}

	// Create the DACL for the child process
	SECURITY_ATTRIBUTES procSa;
	EXPLICIT_ACCESS procEa[2];
	PACL pProcAcl = nullptr;
	PSECURITY_DESCRIPTOR procSD = nullptr;
	SecureZeroMemory(&procEa, 2 * sizeof(EXPLICIT_ACCESS));
	// Broker user have full control over the child process
	procEa[0].grfAccessPermissions = PROCESS_ALL_ACCESS;
	procEa[0].grfAccessMode = SET_ACCESS;
	procEa[0].grfInheritance = NO_INHERITANCE;
	procEa[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	procEa[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
	procEa[0].Trustee.ptstrName = (LPTSTR)g_pBrokerSID;

	// Administrators have full control over the child process
	procEa[1].grfAccessPermissions = PROCESS_ALL_ACCESS;
	procEa[1].grfAccessMode = SET_ACCESS;
	procEa[1].grfInheritance = NO_INHERITANCE;
	procEa[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	procEa[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	procEa[1].Trustee.ptstrName = (LPTSTR)g_pAdministratorsSID;

	dwRes = SetEntriesInAcl(2, procEa, nullptr, &pProcAcl);
	if (dwRes != ERROR_SUCCESS) {
		fprintf(g_logFile, "SetEntriesInAcl() failed: %d\n", GetLastError());
		return false;
	}
	
	procSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (procSD == nullptr) {
		fprintf(g_logFile, "LocalAlloc() failed: %d\n", GetLastError());
		return false;
	}

	if (!InitializeSecurityDescriptor(procSD, SECURITY_DESCRIPTOR_REVISION)) {
		fprintf(g_logFile, "InitializeSecurityDescriptor() failed: %d\n", GetLastError());
		return false;
	}

	if (!SetSecurityDescriptorDacl(procSD, TRUE, pProcAcl, FALSE)) {
		fprintf(g_logFile, "SetSecurityDescriptorDacl() failed: %d\n", GetLastError());
		return false;
	}

	procSa.nLength = sizeof(SECURITY_ATTRIBUTES);
	procSa.lpSecurityDescriptor = procSD;
	procSa.bInheritHandle = TRUE;



	// Start the child process 
	// todo the startup path
	if(CreateProcessAsUser(hUserToken, 0, szChildComandLineBuf, &procSa, 0, TRUE, 0, 0, szUSerHomeDirectory, &si, &pi)) {
		WSAPROTOCOL_INFOW protocoleInfo;
		LPVOID lpView;
		DWORD res;

		if (WSADuplicateSocketW(client, pi.dwProcessId, &protocoleInfo) == SOCKET_ERROR) {
			fprintf(g_logFile, "WSADuplicateSocketW() failed: %d\n", WSAGetLastError());
			return false;
		}

		lpView = MapViewOfFile(ghMMFileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
		if (lpView != nullptr) {
			memcpy(lpView, &protocoleInfo, sizeof(WSAPROTOCOL_INFOW));
			UnmapViewOfFile(lpView);

			SetEvent(ghParentFileMappingEvent);
			if((res = WaitForSingleObject(ghChildFileMappingEvent, 5000)) != WAIT_OBJECT_0) {
				if (res == WAIT_TIMEOUT) {
					fprintf(g_logFile, "WaitForSingleObject() reach timeout!\n");
				}
				else {
					fprintf(g_logFile, "WaitForSingleObject() failed: %d\n", GetLastError());
				}
			}
		}
		else {
			fprintf(g_logFile, "MapViewOfFile() failed: %d\n", GetLastError());
					
		}
			
		CloseHandle(ghMMFileMap);
		ghMMFileMap = nullptr;

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
	else {
		fprintf(g_logFile, "CreateProcessAsUser() failed: %d\n", GetLastError());
		return false;
	}

	if (ghParentFileMappingEvent != nullptr) {
		CloseHandle(ghParentFileMappingEvent);
		ghParentFileMappingEvent = nullptr;
	}

	if (ghChildFileMappingEvent != nullptr) {
		CloseHandle(ghChildFileMappingEvent);
		ghChildFileMappingEvent = nullptr;
	}

	return true;
}