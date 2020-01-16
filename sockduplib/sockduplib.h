
#include <WinSock2.h>
#include <stdio.h>

#ifdef SOCKDUPLIB_EXPORTS
#    define LIBRARY_API __declspec(dllexport)
#else
#    define LIBRARY_API __declspec(dllimport)
#endif


extern "C" LIBRARY_API SOCKET GetSocket(char* ParentEventHandle, char* ChildEventHandle, char* Mmaping);
