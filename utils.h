// Include necessary headers
#include "lazy.h"
#include <Windows.h>
#include <regex>
#include "auth_header.h"
#include "spoof.h"
#include <Shlwapi.h>
#include <aclapi.h>
#include "oxorany_include.h"
#include <filesystem>
#include <fstream>
#include <chrono>
#include <iostream>
#include <Psapi.h>
#include "obfuscator.h"
#include "encrypt.h"
#include "base64.h"
#include <random>
#include "remap.hpp"
#include <tchar.h>
#include <fstream>
#include "hash.h"
#include "resetpeb.h"
#include "injector.h"
#define secure __forceinline

using namespace std;
using namespace base64;
using namespace KeyAuth;

std::string command;
std::string webhookurl;

bool tls_ran = false;
bool logs = false;
bool Authorized = false;
bool Premium = false;
bool bsod = false;
bool main_called = false;
bool block_threads = false;
bool thread1_started = false;
bool thread2_started = false;
bool thread_starter_called = false;
HANDLE Thread1 = 0;
HANDLE Thread2 = 0;
int times;
int time1 = 0;
int time2 = 0;
int called = 0;

typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_ unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(__stdcall* _NtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE);
typedef NTSTATUS(__stdcall* CheckQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

BYTE multiByte[] = { 0xCD, 0x90, 0xCD, 0x03, 0xCD, 0x90 };
#define PAGE_SIZE2 0x1000

#pragma comment(linker, "/ALIGN:0x10000")

namespace fs = std::filesystem;
// Credits to https://luckyware.vip for leaking it
struct SharedData
{
    char message[256];
    char response[256];
    bool isResponseReceived;
};

SharedData* createSharedMemory()
{
    HANDLE hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(SharedData), Encrypt("Specter_Heartbeart_Handle"));
    if (hMapFile == NULL)
    {
        return nullptr;
    }
    return (SharedData*)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedData));
}

void releaseSharedMemory(SharedData* pData) {
    UnmapViewOfFile(pData);
}


void Wait(int milliseconds)
{
    auto start = std::chrono::steady_clock::now();
    auto duration = std::chrono::milliseconds(milliseconds);
    while (std::chrono::steady_clock::now() - start < duration) {}
}
// Credits to https://luckyware.vip for leaking it
void InsertString(string modulestring)
{
    OverwriteReturnAddress;
    int b = Encrypt(4);
    if (b > Encrypt(2))
    {
        b = (5);
    }
}

secure void Junkcode()
{
    CALL(&InsertString, Encrypt("NotHere"));
    times = Encrypt(5);
}
// Credits to https://luckyware.vip for leaking it
void SetProcessCirtical() 
{
    typedef long (WINAPI* RtlSetProcessIsCritical)
        (BOOLEAN New, BOOLEAN* Old, BOOLEAN NeedScb);
    auto ntdll = Lazy(LoadLibraryA).forwarded_safe_cached()("ntdll.dll");
    if (ntdll)
    {
        auto SetProcessIsCritical = (RtlSetProcessIsCritical)
            GetProcAddress(ntdll, Encrypt("RtlSetProcessIsCritical"));
        if (SetProcessIsCritical)
            SetProcessIsCritical(1, 0, 0);
    }
}

auto bluescreenhehe() // cba to encrypt strings so put in func so they cant see where its called
{
    OverwriteReturnAddress; 
    CALL(&SetProcessCirtical);
    BOOLEAN bEnabled; ULONG uResp; LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), ("RtlAdjustPrivilege")); LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle("ntdll.dll"), ("NtRaiseHardError")); pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;  pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2; NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled); NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
}
// Credits to https://luckyware.vip for leaking it
secure auto HandleAttack()
{
    Junkcode();
    if (bsod) // cba to protect this building time would be insane
    { 
        bluescreenhehe();
    }
    Lazy(exit).forwarded_safe_cached()(0x99);
    Lazy(TerminateProcess).forwarded_safe_cached()(GetCurrentProcess(), 0);
    Lazy(_Exit).forwarded_safe_cached()(0);
    Lazy(quick_exit).forwarded_safe_cached()(0);
    Lazy(ExitProcess).forwarded_safe_cached()(0);
    Lazy(abort).forwarded_safe_cached();
    __fastfail(0);
    for (long long int i = 0; ++i; (&i)[i] = i);
    *((char*)NULL) = 0;
    *(uintptr_t*)(0) = 0x99;
    Junkcode();
}
// Credits to https://luckyware.vip for leaking it
bool IsVaildFormat(const std::string& str)
{
    OverwriteReturnAddress;
    std::regex pattern(Encrypt("SS-[a-zA-Z0-9]{4}")); //change
    return std::regex_match(str, pattern);
}
// Credits to https://luckyware.vip for leaking it
void Wipe_String(std::string& str)
{
    std::memset(&str[0], 0, str.size());
    str.clear();
    str = Encrypt(".");
}
// Credits to https://luckyware.vip for leaking it
auto Anti_Swap()
{
    std::ifstream file(Encrypt("C:\\Windows\\System32\\drivers\\etc\\hosts"), std::ios::in | std::ios::binary);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line))
    {
        if (line.find(Encrypt("keyauth")) == std::string::npos)
        {
            lines.push_back(line);
        }
    }
    file.close();
    std::ofstream outFile(Encrypt("C:\\Windows\\System32\\drivers\\etc\\hosts"), std::ios::out | std::ios::binary);
    for (const auto& l : lines)
    {
        outFile << l << std::endl;
    }
    outFile.close();
}
// Credits to https://luckyware.vip for leaking it
auto Authorize(std::string license)
{
    OverwriteReturnAddress; Authorized = true;
    if (IsVaildFormat(license))
    {
        Anti_Swap();
        string name = Encrypt("TGliYXJ5");
        string ownerid = Encrypt("QU5CdVU2TlRGRA");
        string secret = Encrypt("MzczYTM2ZTdjODBkZTMzNGQ3MGZkZjZmZDlkOGFiODcwMmNkNWIzM2FhMzU3Njk5YzEzZTdlMGU2ZDQxYjBlOA");
        string ver = Encrypt("MS4w");
        string authapi = Encrypt("aHR0cHM6Ly9rZXlhdXRoLndpbi9hcGkvMS4yLw");
        api Auth(decode(name).c_str(), decode(ownerid).c_str(), decode(secret).c_str(), decode(ver).c_str(), decode(authapi).c_str(), Encrypt(""));
        block_threads = true; Auth.init(); block_threads = false; // so auth thread doesnt start
        Auth.license(license);
        if (Auth.response.success) 
        {
            auto data = Auth.var(Encrypt("Specter_Data")); Junkcode();
            if (data == Encrypt("1565878891124"))
            {
                for (const api::subscriptions_class& subs : Auth.user_data.subscriptions)
                {
                    if (subs.name == Encrypt("Special"))
                    {
                        Junkcode(); Authorized = true;  Premium = true;
                    }

                }
            }
        }
        Wipe_String(name); Wipe_String(ownerid); Wipe_String(secret); Wipe_String(ver); Wipe_String(authapi); Wipe_String(license);
    }
    Junkcode(); if (!Authorized) { HandleAttack(); }    Junkcode();
}
// Credits to https://luckyware.vip for leaking it
secure void OpenSSFile()
{
    OverwriteReturnAddress;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    RtlZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    RtlZeroMemory(&pi, sizeof(pi));
    std::string command = Encrypt("notepad.exe SS.txt");
    Lazy(CreateProcessA).forwarded_safe_cached()(NULL, const_cast<char*>(command.c_str()), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}
// Credits to https://luckyware.vip for leaking it
secure void ErrorMessage(std::string message)
{
    OverwriteReturnAddress;
    std::ofstream outputFile(Encrypt("SS.txt"));
    if (outputFile.is_open())
    {
        outputFile << message;
        outputFile.close();
    }
    OpenSSFile();
    Lazy(exit).forwarded_safe_cached()(0x99);
}


void System_Real()
{
    OverwriteReturnAddress;
    Lazy(system).forwarded_safe_cached()(command.c_str());
    command.clear(); command = "";
}

void System_Spoofed(std::string cmd)
{
    OverwriteReturnAddress;
    command = cmd;
    if (command == cmd && (Encrypt(1)))
    {
        CALL(&System_Real);
    }
}
// Credits to https://luckyware.vip for leaking it
bool HideThread(HANDLE hThread) 
{
    _NtSetInformationThread NtSetInformationThread = (_NtSetInformationThread)Lazy(GetProcAddress)(Lazy(LoadLibraryA).forwarded_safe_cached()(Encrypt("ntdll.dll")), Encrypt("NtSetInformationThread"));
    if (!NtSetInformationThread) { return false; }

    NTSTATUS Status = NtSetInformationThread(hThread, 0x11, NULL, NULL);
    if (!NT_SUCCESS(Status)) { return false; }

    return true;
}
bool ChangePerms(HANDLE thread)
{
    typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
    NTSTATUS Status;

    pNtSetInformationThread NtSIT = (pNtSetInformationThread)Lazy(GetProcAddress).forwarded_safe_cached()((Lazy(GetModuleHandleA).forwarded_safe_cached())("ntdll.dll"), Encrypt("NtSetInformationThread"));

    if (NtSIT == NULL) return false;
    if (thread == NULL)
        Status = NtSIT(Lazy(GetCurrentThread).forwarded_safe_cached(), 0x11, 0, 0);
    else
        Status = NtSIT(thread, 0x11, 0, 0);

    if (Status != 0x00000000)
        return false;
    else
        return true;
}

bool hide_thread_from_debugger()
{
    typedef NTSTATUS(WINAPI* pNtSetInformationThread)(IN HANDLE, IN UINT, IN PVOID, IN ULONG);

    const int ThreadHideFromDebugger = 0x11;
    pNtSetInformationThread NtSetInformationThread = NULL;

    NTSTATUS Status;
    BOOL IsBeingDebug = FALSE;

    HMODULE hNtDll = Lazy(LoadLibraryA).forwarded_safe_cached()(Encrypt("ntdll.dll"));
    NtSetInformationThread = (pNtSetInformationThread)Lazy(GetProcAddress).forwarded_safe_cached()(hNtDll, Encrypt("NtSetInformationThread"));
    Status = NtSetInformationThread(Lazy(GetCurrentThread).forwarded_safe_cached()(), ThreadHideFromDebugger, NULL, 0);

    if (Status)
        *(uintptr_t*)(0) = 1;

    return IsBeingDebug;
}
// Credits to https://luckyware.vip for leaking it
bool Hide(HANDLE thread)
{
    typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
    NTSTATUS Status;

    pNtSetInformationThread NtSIT = (pNtSetInformationThread)Lazy(GetProcAddress).forwarded_safe_cached()((Lazy(GetModuleHandleA).forwarded_safe_cached())(Encrypt("ntdll.dll")), Encrypt("NtSetInformationThread"));

    if (NtSIT == NULL) return false;
    if (thread == NULL)
        Status = NtSIT(Lazy(GetCurrentThread).forwarded_safe_cached(), 0x11, 0, 0);
    else
        Status = NtSIT(thread, 0x11, 0, 0);

    if (Status != 0x00000000)
        return false;
    else
        return true;
}
// Credits to https://luckyware.vip for leaking it
void Stop_Reversing_Retard()
{
    for (;;)
    {
        Lazy(Sleep).forwarded_safe_cached()(999999999999999999);
        Lazy(Sleep).forwarded_safe_cached()(999999999999999999);
        Lazy(Sleep).forwarded_safe_cached()(999999999999999999);
    }
}
// Credits to https://luckyware.vip for leaking it
void Entry_Point_Caller()
{
    Junkcode();
}