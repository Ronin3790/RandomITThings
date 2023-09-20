include <Windows.h>
#include <stdio.h>

int Error(const char* message) {
	printf("%s (error=%d)", message, ::GetLastError());
	return 1;

}


int main()
{
	HANDLE hMemMap = ::CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 1 << 20, L"MySharedMem");
	if (!hMemMap)
		return Error("Failed to open/create MMF");
	printf("Shared memory %s successfully\n", ::GetLastError() == ERROR_ALREADY_EXISTS ? "opened" : "created");

	for (;;) {
		printf("Options: 1=Read 2=Write 0=Quit: ");
		int option;
		scanf_s("%d", &option);
		if (option == 0)
			break;

		if (option == 2) {
			void* p = ::MapViewOfFile(hMemMap, FILE_MAP_WRITE, 0, 0, 1 << 16);
			if (!p)
				return Error("Out of memory");

			printf("Enter text: ");
			char text[256];
			while (*gets_s(text) == '\0');

			strcpy_s((char*)p, sizeof(text), text);
			UnmapViewOfFile(p);
		}
		else if (option == 1) {
			void* p = ::MapViewOfFile(hMemMap, FILE_MAP_READ, 0, 0, 1 << 16);
			if (!p)
				return Error("Out of memory");

			printf("Data: %s\n", (const char*)p);
			::UnmapViewOfFile(p);
		}
	}
	::CloseHandle(hMemMap);
