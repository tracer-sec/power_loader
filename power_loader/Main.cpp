#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <codecvt>
#include <sstream>

using namespace std;

typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

class Module
{
public:
    Module(wstring dllPath);
    ~Module();
    
    FARPROC GetProcAddress(string name);

private:
    HMODULE module_;
    IMAGE_NT_HEADERS ntHeader_;
    string error_;
};

Module::Module(wstring dllPath)
{
    SYSTEM_INFO systemInfo;
    ::GetSystemInfo(&systemInfo);

    // Open DLL and read headers
    ifstream f(dllPath, ifstream::binary | ifstream::ate);
    size_t fileSize = f.tellg();
    f.seekg(0, ifstream::beg);

    IMAGE_DOS_HEADER dosHeader;
    //IMAGE_NT_HEADERS ntHeader;

    f.read(reinterpret_cast<char *>(&dosHeader), sizeof(dosHeader));
    f.seekg(dosHeader.e_lfanew, ifstream::beg);
    f.read(reinterpret_cast<char *>(&ntHeader_), sizeof(ntHeader_));

    vector<IMAGE_SECTION_HEADER> sections(ntHeader_.FileHeader.NumberOfSections);

    f.read(reinterpret_cast<char *>(&sections[0]), sizeof(IMAGE_SECTION_HEADER) * ntHeader_.FileHeader.NumberOfSections);

    // Allocate memory
    LPVOID preferredBase = nullptr; //reinterpret_cast<LPVOID>(ntHeader.OptionalHeader.ImageBase);
    auto buffer = ::VirtualAlloc(preferredBase, ntHeader_.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD baseAddress = reinterpret_cast<DWORD>(buffer);

    // Copy sections into memory
    for (auto section : sections)
    {
        f.seekg(section.PointerToRawData, ifstream::beg);

        auto size = section.SizeOfRawData;
        if (size == 0)
        {
            if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                size = ntHeader_.OptionalHeader.SizeOfUninitializedData;
            else if (section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
                size = ntHeader_.OptionalHeader.SizeOfInitializedData;
        }

        f.read(reinterpret_cast<char *>(baseAddress) + section.VirtualAddress, size);
    }

    // All in memory. Ditch the file.
    f.close();

    // Process import table
    IMAGE_DATA_DIRECTORY importTable = ntHeader_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    unsigned int importOffset = baseAddress + importTable.VirtualAddress;
    unsigned int importEnd = baseAddress + importTable.VirtualAddress + importTable.Size;

    wstring_convert<codecvt_utf8<wchar_t>> converter;
    while (importOffset < importEnd)
    {
        IMAGE_IMPORT_DESCRIPTOR *import = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(importOffset);
        char *name = reinterpret_cast<char *>(baseAddress + import->Name);
        wstring moduleName = converter.from_bytes(name);

        // Load library
        auto handle = ::LoadLibrary(moduleName.c_str());

        // Resolve functions
        DWORD *names = reinterpret_cast<DWORD *>(baseAddress + import->OriginalFirstThunk);
        DWORD *addresses = reinterpret_cast<DWORD *>(baseAddress + import->FirstThunk);

        while (*names)
        {
            IMAGE_THUNK_DATA *thunk = reinterpret_cast<IMAGE_THUNK_DATA *>(names);

            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.AddressOfData)) // import by ordinal
            {
                int ordinal = thunk->u1.Ordinal & 0x7fff;
                *addresses = reinterpret_cast<DWORD>(::GetProcAddress(handle, reinterpret_cast<LPCSTR>(ordinal)));
            }
            else // import by name
            {
                IMAGE_IMPORT_BY_NAME *nameThunk = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(baseAddress + thunk->u1.AddressOfData);
                *addresses = reinterpret_cast<DWORD>(::GetProcAddress(handle, nameThunk->Name));
            }

            names ++;
            addresses ++;
        }

        importOffset += sizeof(*import);
    }

    // Load and process relocation table
    auto relocationValue = static_cast<int32_t>(baseAddress - ntHeader_.OptionalHeader.ImageBase);
    IMAGE_DATA_DIRECTORY relocationTable = ntHeader_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    unsigned int endOfRelocation = baseAddress + relocationTable.VirtualAddress + relocationTable.Size;
    unsigned int offset = baseAddress + relocationTable.VirtualAddress;

    while (offset < endOfRelocation)
    {
        IMAGE_BASE_RELOCATION *block = reinterpret_cast<IMAGE_BASE_RELOCATION *>(offset);
        for (int i = sizeof(*block); i < block->SizeOfBlock; i += 2)
        {
            uint16_t *foo = reinterpret_cast<uint16_t *>(reinterpret_cast<char *>(block) + i);

            int type = *foo >> 12;
            int value = *foo & 0xfff;

            int32_t diff = 0;
            if (type == IMAGE_REL_BASED_HIGHLOW)
            {
                DWORD target = baseAddress + block->VirtualAddress + value;
                int32_t *v = reinterpret_cast<int32_t *>(target);
                int32_t foo = *v;
                *v += relocationValue;
                int32_t bar = *v;

                diff = foo - bar;
            }
        }
        offset += block->SizeOfBlock;
    }

    // Fix memory protection
    for (auto section : sections)
    {
        DWORD oldValue;
        DWORD newValue = PAGE_READONLY;

        if (section.Characteristics & IMAGE_SCN_MEM_READ && section.Characteristics & IMAGE_SCN_MEM_WRITE && section.Characteristics & IMAGE_SCN_MEM_WRITE)
            newValue = PAGE_EXECUTE_READWRITE;
        else if (section.Characteristics & IMAGE_SCN_MEM_READ && section.Characteristics & IMAGE_SCN_MEM_WRITE)
            newValue = PAGE_READWRITE;
        else if (section.Characteristics & IMAGE_SCN_MEM_READ && section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            newValue = PAGE_EXECUTE_READ;

        auto size = section.SizeOfRawData;
        if (size == 0)
        {
            if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                size = ntHeader_.OptionalHeader.SizeOfUninitializedData;
            else if (section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
                size = ntHeader_.OptionalHeader.SizeOfInitializedData;
        }

        if (size == 0)
            continue;

        auto result = ::VirtualProtect(reinterpret_cast<char *>(baseAddress) + section.VirtualAddress, size, newValue, &oldValue);

        if (result == 0)
        {
            auto boo = ::GetLastError();
            ostringstream ss;
            ss << "Shit's broke, yo: " << boo;
            error_ = ss.str();
            return;
        }
    }

    // Call DllMain
    DllEntryProc entry = reinterpret_cast<DllEntryProc>(baseAddress + ntHeader_.OptionalHeader.AddressOfEntryPoint);
    (*entry)(reinterpret_cast<HINSTANCE>(baseAddress), DLL_PROCESS_ATTACH, 0);

    // Yay!
    module_ = reinterpret_cast<HMODULE>(baseAddress);
}

Module::~Module()
{
    // Going to need a FreeLibrary equivalent in here ...
}

FARPROC Module::GetProcAddress(string name)
{
    DWORD baseAddress = reinterpret_cast<DWORD>(module_);
    IMAGE_DATA_DIRECTORY exportTable = ntHeader_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *e = reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(baseAddress + exportTable.VirtualAddress);

    // Resolve functions
    DWORD *names = reinterpret_cast<DWORD *>(baseAddress + e->AddressOfNames);
    WORD *ordinals = reinterpret_cast<WORD *>(baseAddress + e->AddressOfNameOrdinals);

    while (*names)
    {
        string currentName(reinterpret_cast<char *>(baseAddress + *names));
        if (name == currentName)
        {
            break;
        }

        names++;
        ordinals++;
    }

    DWORD *offset = reinterpret_cast<DWORD *>(baseAddress + e->AddressOfFunctions + (*ordinals * 4));
    auto procAddress = baseAddress + reinterpret_cast<char *>(*offset);

    return reinterpret_cast<FARPROC>(procAddress);
}

typedef int(*AddProc)(int a, int b);
typedef bool(*CompareProc)(string foo, string bar);

int WINAPI WinMain(HINSTANCE instance, HINSTANCE prevInstance, LPSTR commandLine, int show)
{
    Module dll(L"dll_test.dll");

    int result = -1;
    AddProc add = reinterpret_cast<AddProc>(dll.GetProcAddress("Add"));
    if (add)
        result = (*add)(4, 9);

    cout << result << endl;

    bool comp = false;
    CompareProc compare = reinterpret_cast<CompareProc>(dll.GetProcAddress("Compare"));
    if (compare)
        comp = (*compare)("test111", "test111");

    cout << comp << endl;

    return 0;
}
