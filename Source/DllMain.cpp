/*
    Initial author: (https://github.com/)Convery
    License: LGPL 3.0
    Started: 2015-10-21
    Notes:
        The modules should not have to check if an applications memory is writable.
        As such, we need to unprotect the host application.
*/

#include <Windows.h>

// Original code and address to restore the state later.
unsigned char OriginalText[20];
size_t OriginalEntrypoint{};

// Replacement entrypoint.
void Initialcall()
{
    // Load the debug modules into the process.
    LoadLibraryA("Pluginloader");
    LoadLibraryA("AyriaDeveloper");
    LoadLibraryA("LocalDeveloper");

    // Restore the original entrypoint.
    memcpy((void *)OriginalEntrypoint, OriginalText, 20);

    // Stack alignment is needed in 64bit hosts.
#ifdef _WIN64
    __asm and rsp, 0xFFFFFFFFFFFFFFF0;
    __asm push 0xDEADDEADDEADDEAD;
#endif

    // Continue execution at the original entrypoint.
    __asm jmp OriginalEntrypoint;
}

// Make the host application writeable.
void UnprotectModule(HMODULE Module)
{
    PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)Module;
    PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)Module + DOSHeader->e_lfanew);
    SIZE_T Size = NTHeader->OptionalHeader.SizeOfImage;

    VirtualProtect((void *)Module, Size, PAGE_EXECUTE_READWRITE, NULL);
}

// Reusable way to fetch the entrypoint.
size_t GetEntryPoint(HMODULE Module)
{
    PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)Module;
    PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)Module + DOSHeader->e_lfanew);
    return (size_t)((DWORD_PTR)Module + NTHeader->OptionalHeader.AddressOfEntryPoint);
}

// Initialize the modification.
BOOL SafeInitialization()
{
    HMODULE Module = GetModuleHandleA(NULL);

    // This should never be hit.
    if (!Module) return FALSE;

    // Make the module writable.
    UnprotectModule(Module);

    // Save the state of the entrypoint.
    OriginalEntrypoint = GetEntryPoint(Module);
    memcpy(OriginalText, (void *)OriginalEntrypoint, 20);
    memset((void *)OriginalEntrypoint, 0x90, 20);

    // Add a jump at the entrypoint.
#ifdef _WIN64
    *(unsigned char *)(OriginalEntrypoint + 0) = 0x48;          // mov
    *(unsigned char *)(OriginalEntrypoint + 1) = 0xB8;          // rax
    *(size_t *)(OriginalEntrypoint + 2) = (size_t)Initialcall;
    *(unsigned char *)(OriginalEntrypoint + 10) = 0xFF;         // jmp reg
    *(unsigned char *)(OriginalEntrypoint + 11) = 0xE0;         // rax
#else
    *(unsigned char *)(OriginalEntrypoint + 0) = 0xE9;          // jmp
    *(size_t *)(OriginalEntrypoint + 1) = ((size_t)Initialcall - (OriginalEntrypoint + 5));
#endif

    return TRUE;
}

// Bootstrap entrypoint.
BOOL __stdcall DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        // Initialize the modification.
        return SafeInitialization();
    }

    return TRUE;
}
