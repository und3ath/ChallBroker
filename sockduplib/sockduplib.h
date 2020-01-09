
#include <WinSock2.h>
#include <stdio.h>

#ifdef LIBRARY_EXPORTS
#    define LIBRARY_API __declspec(dllexport)
#else
#    define LIBRARY_API __declspec(dllimport)
#endif


LIBRARY_API SOCKET GetSocket(char* szFileMapObj);
