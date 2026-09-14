#include <windows.h>
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")

static void BuildPath(char* out, int outSize, const char* folder, const char* file)
{
    int len;
    lstrcpynA(out, folder, outSize);
    len = lstrlenA(out);
    if (len > 0 && out[len - 1] != '\\')
    {
        lstrcatA(out, "\\");
    }

    lstrcatA(out, file);
}

static BOOL FileExists(const char* path)
{
    DWORD attr = GetFileAttributesA(path);
    return (attr != 0xFFFFFFFF && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

static BOOL InjectDll(HANDLE hProcess, const char* dllFullPath)
{
    DWORD pathLen = lstrlenA(dllFullPath) + 1;
    LPVOID remoteBuf;
    HANDLE hThread;
    LPTHREAD_START_ROUTINE pLoadLibrary;

    remoteBuf = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf)
    {
        MessageBoxA(NULL, "VirtualAllocEx failed", "Injector Error", MB_OK | MB_ICONERROR);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, remoteBuf, (LPVOID)dllFullPath, pathLen, NULL))
    {
        MessageBoxA(NULL, "WriteProcessMemory failed", "Injector Error", MB_OK | MB_ICONERROR);
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibrary)
    {
        MessageBoxA(NULL, "GetProcAddress(LoadLibraryA) failed", "Injector Error", MB_OK | MB_ICONERROR);
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, remoteBuf, 0, NULL);
    if (!hThread)
    {
        MessageBoxA(NULL, "CreateRemoteThread failed", "Injector Error", MB_OK | MB_ICONERROR);
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    CloseHandle(hThread);
    return TRUE;
}

int main(int argc, char* argv[])
{
    char searchFolder[MAX_PATH];
    char exePath[MAX_PATH];
    char dllPath[MAX_PATH];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    const char* exeName = "AdvanceBox.exe";
    const char* dllName = "emulator.dll";

    GetCurrentDirectoryA(MAX_PATH, searchFolder);

    if (!FileExists(exeName) || !FileExists(dllName))
    {
        MessageBoxA(NULL, "Executable not found. Check file name of the app and dll.", "Injector Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    BuildPath(exePath, MAX_PATH, searchFolder, exeName);
    BuildPath(dllPath, MAX_PATH, searchFolder, dllName);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(exePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, searchFolder, &si, &pi))
    {
        MessageBoxA(NULL, "CreateProcess failed.", "Injector Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    if (!InjectDll(pi.hProcess, dllPath)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    ResumeThread(pi.hThread);
    WaitForInputIdle(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
