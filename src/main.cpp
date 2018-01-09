// General
#include <stdio.h>
#include <Windows.h>

// xHacking library
// INCLUDE ORDER IS, **IS**, IMPORTANT!
// If not done in this order, functions such as Detour::Wait (depens on Loader) would not be available
#include <xhacking/xHacking.h>
#include <xhacking/Utilities/Utilities.h>
#include <xhacking/Loader/Loader.h>
#include <xhacking/Detour/Detour.h>
using namespace xHacking;

#ifdef _DEBUG
#pragma comment(lib, "xHacking_d.lib")
#else
#pragma comment(lib, "xHacking.lib")
#endif

// Variables which will hold the detours
Detour<int, int, char*, int, int>* recvDetour = NULL;
Detour<int, int, char*, int, int>* sendDetour = NULL;
Detour<hostent*, char*>* gethostbynameDetour = NULL;

// Commented example, not used
//Detour<int, int, char*, int, int>* sendMemory = NULL;

hostent* WINAPI nuestro_gethostbyname(char *buf)
{
	// Calling the original function
	__asm PUSHAD;
	__asm PUSHFD;

	// Custom code

	


		printf("%s ---> localhost \n", buf);

		char localhost[] = "localhost";
	
	

	

	__asm POPFD;
	__asm POPAD;
	//__asm ret;

	return (*gethostbynameDetour)(localhost);
	
}




int WINAPI nuestro_recv(SOCKET s, char *buf, int len, int flags)
{
	// Calling the original function
	int ret = (*recvDetour)(s, buf, len, flags);

	__asm PUSHAD;
	__asm PUSHFD;

	printf("Comienza recvDetour\n");

	int i = 0;
	while (i < ret) {
		printf("%c", buf[0]);
		buf++;
		i++;
	
	}

	printf("\n");
	__asm POPFD;
	__asm POPAD;

	return ret;
}
// NOTE: unk0 is due to detouring 5 bytes from function start (as seen below)
// and, probably, unk0 = EBP
int WINAPI nuestro_send( SOCKET s, char *buf, int len, int flags)
{

	//int ret = (*sendDetour)(unk0,s, buf, len, flags);

	__asm PUSHAD;
	__asm PUSHFD;

	printf("Comienza SendDetour\n");
	printf("%s\n", buf);




	__asm POPFD;
	__asm POPAD;

	return 0;
}



// This is asyncrouneusly (or sync if the DLL is already loaded) by the xHacking::Loader class
void hookSend(Loader::Data* data)
{
	// We are performing the detour on +5 bytes, including a trampoline, so that's why we are doing
	// it this way.
	// It is, somehow, an example of a mid-function hooking
	sendDetour = new Detour< int, int, char*, int, int>(data->Function + 0, (BYTE*)nuestro_send);
	sendDetour->WithTrampoline(true)->Commit();





	// A trampoline is basically some code to automatically return to the original program flow.

}


void hookGethostbyname(Loader::Data* data)
{
	// We are performing the detour on +5 bytes, including a trampoline, so that's why we are doing
	// it this way.
	// It is, somehow, an example of a mid-function hooking
	gethostbynameDetour = new Detour<hostent*, char*>(data->Function + 5, (BYTE*)nuestro_gethostbyname);
	gethostbynameDetour->WithTrampoline(true)->Commit();



}

void Hooks()
{
	// We first create the recv detour.
	// We want it to be automatically created whenever WSOCK32 is loaded (and not load it),
	// Thus, we use the `Wait` function in Detour.
	// If we wanted to force load the DLL, we could use `Load`

	// int WINAPI recv(int, char*, int, int);
	recvDetour = new Detour<int, int, char*, int, int>();
	recvDetour->Wait("WS2_32.dll", "recv", (BYTE*)nuestro_recv);
	printf("[!]recvDetour\n");


	gethostbynameDetour = new Detour<hostent*, char*>();
	gethostbynameDetour->Wait("WS2_32.dll", "gethostbyname", (BYTE*)nuestro_gethostbyname);
	printf("[!]gethostbynameDetour\n");

	//Detour<int, int, int, char*, int, int>* sendDetour = NULL;
	/*
	sendDetour = new Detour<int, int, int, char*, int, int>();
	sendDetour->Wait("WS2_32.dll", "send", (BYTE*)nuestro_send);
	printf("[!]sendDetour\n");
	*/


	// We could specify the Detour type by calling `Type(DETOUR_X)` where DETOUR_X is defined in
	// DETOUR_TYPE. That call should be done BEFORE the wait call, unexpected behaviour may happen
	// otherwise

	// Here we use the Loader class to wait for the WS2_32 dll
	// Once it is loaded, the function `hookSend` will be called

	Loader::Wait("WS2_32.dll", "send", hookSend);

	//printf("sendDetour\n");

}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, DWORD reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		// Use the xHacking::CreateConsole function
		CreateConsole();
		printf("---Start Console---\n");

		// Call our function
		Hooks();
	}

	return true;
}
