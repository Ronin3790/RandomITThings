#include <Windows.h>
#include <stdio.h>

const int cellSize = 256;
const int maxCellX = 10240;
const int maxCellY = 10240;

int DoCommit(void* address) {
	if (!::VirtualAlloc(address, cellSize, MEM_COMMIT, PAGE_READWRITE))
		return EXCEPTION_CONTINUE_SEARCH;
	return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
	BYTE* buffer = (BYTE*)::VirtualAlloc(nullptr, (SIZE_T) cellSize * maxCellX * maxCellY, MEM_RESERVE, PAGE_READWRITE);
	if (!buffer)
		return 1;

	printf("Buffer: 0x%p\n", buffer);

	for (;;) {
		printf("Options: 1:Read 2:Write 0:Quit: ");
		int option;
		scanf_s("%d", &option);
		if (option == 0)
			break;

		if (option < 1 || option > 2) {
			printf("Unknown option.\n");
			continue;

			printf("Enter cell x,y: ");
			int x, y;
			scanf_s("%d,%d", &x, &y);
			if (x < 0 || y < 0 || x >= maxCellX || y >= maxCellY) {
				printf("Out of range.\n");
				continue;
			}

			BYTE* address = buffer + ((SIZE_T)y * maxCellX + x) * cellSize;
			if (option == 1) {
				__try {
					printf("Data: %s\n", (const char*)address);
				}

				__except (EXCEPTION_EXECUTE_HANDLER) {
					printf("Error! Cell not commited\n");
				}
			}
			else {
				__try {
					sprintf_s((char*)address, cellSize, "Data stored in cell (%d, %d)", x, y);
				}
				__except (DoCommit(address)) {

				}
			}
	}
	}
    return 0;
}

