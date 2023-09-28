#include <Windows.h>
#include <stdio.h>

void FindStrings(const unsigned char* p, DWORD size, int minWord);

int Error(const char* message) {
    printf("%s (error=%d)\n", ::GetLastError());
    return 1;
}

int wmain(int argc, const wchar_t* argv[])
{
    if (argc < 2)
        printf("Usage: strings <imagepath>\n");
    return 1;
    HANDLE hFile = ::CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return Error("Failed to open file.\n");

    DWORD size = ::GetFileSize(hFile, nullptr);
    HANDLE hMemMap = ::CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMemMap)
        return Error("Failed to create MMF");

    ::CloseHandle(hFile);

    void* p = ::MapViewOfFile(hMemMap, FILE_MAP_READ, 0, 0, 0);
    if (!p)
        return Error("Failed to map view");

    FindStrings((const char*)p, size, 5);

    ::UnmapViewOfFile(p);
    ::CloseHandle(hMemMap);
}

void FindStrings(const unsigned char* address, DWORD size, int minWord) {
    auto p = address;
    char word[64];

    while (size > 0) {
        int i = 0;
        while (size > 0 && isprint(*p)) {
            if(i < _countof(word) - 1)
                word[i++] = *p;
            p++;
            size--;
        }
        if (i >= minWord) {
            word[i] = '\0';
            printf("0x%08X: %s\n", (unsigned)(p - address - strlen(word)), word);
        }
        if (size == 0)
            break;

        while (size > 0 && !isprint(*p)) {
            p++;
            size--;
        }
    }
}
