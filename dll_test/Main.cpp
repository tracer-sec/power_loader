#include <Windows.h>
#include <string>

using namespace std;

extern "C" __declspec(dllexport) int __cdecl Add(int a, int b)
{
    return a + b;
}

extern "C" __declspec(dllexport) bool __cdecl Compare(string foo, string bar)
{
    return foo == bar;
}

bool WINAPI DllMain(HINSTANCE handle, DWORD reason, LPVOID reserved)
{
    return true;
}
