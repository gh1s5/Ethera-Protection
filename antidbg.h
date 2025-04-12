#include "antivm.h"


secure auto int3bs()
{
    PBYTE Memory = (PBYTE)Lazy(VirtualAlloc).forwarded_safe_cached()(NULL, (PAGE_SIZE2 * 2), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    PBYTE locationMultiByte = &Memory[PAGE_SIZE2 - sizeof(multiByte)];
    PBYTE locationPageTwo = &Memory[PAGE_SIZE2];
    Lazy(memcpy).forwarded_safe_cached()(locationMultiByte, multiByte, sizeof(multiByte));
    PSAPI_WORKING_SET_EX_INFORMATION wsi;
    wsi.VirtualAddress = locationPageTwo;
    Lazy(K32QueryWorkingSetEx).forwarded_safe_cached()(((HANDLE)-1), &wsi, sizeof(wsi));
    __try
    {
        ((void(*)())locationMultiByte)();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    Lazy(K32QueryWorkingSetEx).forwarded_safe_cached()(((HANDLE)-1), &wsi, sizeof(wsi));

    if (memcmp(locationMultiByte, multiByte, sizeof(multiByte)) != 0)
    {
        Lazy(exit).forwarded_safe_cached()(0x992b);
        __fastfail(0x992b);
    }

    if (wsi.VirtualAttributes.Valid)
    {
        Lazy(exit).forwarded_safe_cached()(0x992b);
        __fastfail(0x992b);
    }

    Lazy(VirtualFree).forwarded_safe_cached()(Memory, 0, MEM_RELEASE);
}

secure auto unloadntdll()
{
    HANDLE process = Lazy(GetCurrentProcess).forwarded_safe_cached()();
    MODULEINFO mi = {};
    HMODULE ntdllModule = Lazy(GetModuleHandleA).forwarded_safe_cached()(Encrypt("ntdll.dll"));

    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
    HANDLE ntdllFile = Lazy(CreateFileA).forwarded_safe_cached()(Encrypt("c:\\windows\\system32\\ntdll.dll"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID ntdllMappingAddress = Lazy(MapViewOfFile).forwarded_safe_cached()(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!Lazy(strcmp).forwarded_safe_cached()((char*)hookedSectionHeader->Name, (char*)Encrypt(".text"))) {
            DWORD oldProtection = 0;
            bool isProtected = Lazy(VirtualProtect).forwarded_safe_cached()((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            Lazy(memcpy).forwarded_safe_cached()((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
            isProtected = Lazy(VirtualProtect).forwarded_safe_cached()((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
        }
    }

    Lazy(CloseHandle).forwarded_safe_cached()(process);
    Lazy(CloseHandle).forwarded_safe_cached()(ntdllFile);
    Lazy(CloseHandle).forwarded_safe_cached()(ntdllMapping);
    Lazy(FreeLibrary).forwarded_safe_cached()(ntdllModule);
}

void ntdllcheck()
{
    called = called + 1;
    if (called < 7) // if called to many times will crash exe
    {
        int time = Lazy(GetTickCount64).forwarded_safe_cached()();
        for (int i = 0; i < 200; ++i) { unloadntdll(); }
        int time2 = Lazy(GetTickCount64).forwarded_safe_cached()();
        if (time2 - time > 1750 || time < 1 || time2 < 1) // time val checks incase of hooks
        {
            HandleAttack();
        }
    }
}


auto Antidll()
{
    for (int i = 0; i < 200; ++i) { int3bs(); } 
    PROCESS_MITIGATION_ASLR_POLICY policyInfo;
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY PMCFGP{};
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY PMBSP{};
    PROCESS_MITIGATION_DEP_POLICY PMDP{};
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY PMILP{};
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy = { 0 };     // Strict Handle Check Policy
    policyInfo.EnableBottomUpRandomization = 1;
    policyInfo.EnableForceRelocateImages = 1;
    policyInfo.EnableHighEntropy = 1;
    policyInfo.DisallowStrippedImages = 0;
    PMCFGP.EnableControlFlowGuard = 1;
    PMBSP.MicrosoftSignedOnly = 1;
    PMCFGP.StrictMode = 1;
    PMDP.Permanent = 1;
    PMDP.Enable = 1;
    PMILP.PreferSystem32Images = TRUE;
    PMILP.NoRemoteImages = TRUE;
    PMILP.NoLowMandatoryLabelImages = TRUE;
    handlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
    handlePolicy.HandleExceptionsPermanentlyEnabled = 1;
    Obfuscate(SetProcessMitigationPolicy)(ProcessASLRPolicy, &policyInfo, sizeof(policyInfo));
    Obfuscate(SetProcessMitigationPolicy)(ProcessSignaturePolicy, &PMBSP, sizeof(PMBSP));
    Obfuscate(SetProcessMitigationPolicy)(ProcessImageLoadPolicy, &PMILP, sizeof(PMILP));
    Obfuscate(SetProcessMitigationPolicy)(ProcessStrictHandleCheckPolicy, &handlePolicy, sizeof(handlePolicy));

}

bool ChangePEEntryPoint(DWORD newEntry)
{
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS pNtH;
    DWORD protect = 0;
    HINSTANCE hInst = Lazy(GetModuleHandleW).forwarded_safe_cached()(NULL);

    if (!hInst)
        return false;

    pDoH = (PIMAGE_DOS_HEADER)(hInst);
    pNtH = (PIMAGE_NT_HEADERS)((PIMAGE_NT_HEADERS)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));

    if (pNtH)
    {
        UINT64 pEntry = (UINT64)&pNtH->OptionalHeader.AddressOfEntryPoint;

        if (pEntry)
        {
            Lazy(VirtualProtect).forwarded_safe_cached()((LPVOID)pEntry, sizeof(DWORD), PAGE_READWRITE, &protect);

            __try
            {
                memcpy((void*)&pEntry, (void*)&newEntry, sizeof(DWORD));
                Lazy(VirtualProtect).forwarded_safe_cached()((LPVOID)pEntry, sizeof(DWORD), protect, &protect);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Lazy(VirtualProtect).forwarded_safe_cached()((LPVOID)pEntry, sizeof(DWORD), protect, &protect);
                return false;
            }
        }
    }

    return false;
}

std::string GetCurrentExeName()
{
    char path[MAX_PATH];

    if (GetModuleFileName(NULL, path, MAX_PATH))
    {
        std::string fullPath(path);
        size_t pos = fullPath.find_last_of("\\/");
        return fullPath.substr(pos + 1);
    }
    return ""; 
}


bool ChangeNumberOfSections(DWORD newSectionsCount)
{
    PIMAGE_SECTION_HEADER sectionHeader = 0;
    HINSTANCE hInst = NULL;
    PIMAGE_DOS_HEADER pDoH = 0;
    PIMAGE_NT_HEADERS64 pNtH = 0;

    hInst = Lazy(GetModuleHandleA).forwarded_safe_cached()(GetCurrentExeName().c_str());

    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    if (pDoH == NULL || hInst == NULL)
    {
        return false;
    }

    pNtH = (PIMAGE_NT_HEADERS64)((PIMAGE_NT_HEADERS64)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));
    sectionHeader = IMAGE_FIRST_SECTION(pNtH);

    DWORD dwOldProt = 0;

    if (!Lazy(VirtualProtect).forwarded_safe_cached()((LPVOID)&pNtH->FileHeader.NumberOfSections, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProt))
    {
        return false;
    }

    Lazy(memcpy).forwarded_safe_cached()((void*)&pNtH->FileHeader.NumberOfSections, (void*)&newSectionsCount, sizeof(DWORD));

    if (!Lazy(VirtualProtect).forwarded_safe_cached()((LPVOID)&pNtH->FileHeader.NumberOfSections, sizeof(DWORD), dwOldProt, &dwOldProt)) //reset page protections
    {
        return false;
    }

    return true;
}

secure auto CheckOperatingSystem()
{
    bool SupportedSystem = false;
#ifdef _WIN64
    SupportedSystem = true;
#elif _WIN32
    SupportSystemed = true;
#else
    SupportSystemed = false;
#endif


    if (!SupportedSystem)
    {
        HandleAttack();
    }
}


secure auto DetectProcessHacker()
{
    std::vector<const wchar_t*> Events =
    {
        Encrypt(L"Global\\ProcessHacker"),
        Encrypt(L"Global\\SystemInformer"),
    };

    for (const auto& Handle : Events)
    {
        HANDLE eventHandle = Lazy(OpenEventW).forwarded_safe_cached()(EVENT_ALL_ACCESS, FALSE, Handle);
        DWORD dwError = GetLastError();
        if (dwError == ERROR_INVALID_HANDLE || dwError == ERROR_SUCCESS)
        {
            HandleAttack();
        }
    }
}


bool CloseInvalidHandle()
{
    __try { Lazy(CloseHandle).forwarded_safe_cached()((HANDLE)0x99999999ULL); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return TRUE; }
}

bool RaiseDbgControl()
{
    __try { Lazy(RaiseException).forwarded_safe_cached()(DBG_CONTROL_C, 0, 0, NULL); return true; }
    __except (GetExceptionCode() == DBG_CONTROL_C ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { return false; }
}

#pragma intrinsic(_ReturnAddress)

auto NoStepie()
{
    PVOID pRetAddress = _ReturnAddress();
    if (*(PBYTE)pRetAddress == 0xCC)
    {
        DWORD dwOldProtect;
        if (Lazy(VirtualProtect).forwarded_safe_cached()(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        {
            *(PBYTE)pRetAddress = 0x90;
            Lazy(VirtualProtect).forwarded_safe_cached()(pRetAddress, 1, dwOldProtect, &dwOldProtect);

            HandleAttack();
        }
    }
}

BOOL CALLBACK Specter_Module(HWND hwnd, LPARAM lParam) {
    std::vector<std::string> windowTitles = { Encrypt("hacker"), Encrypt("Resource Monitor"), Encrypt(") Properties"), Encrypt("(Administrator)"), Encrypt("dexz") };
    std::vector<std::string> windowClassNames = { Encrypt("ProcessHacker"), Encrypt("#32770"), Encrypt("Qt5QWindowIcon"), Encrypt("WindowsForms10.Window.8.app.0.378734a"), Encrypt("MainWindowClassName"), Encrypt("BrocessRacker") };

    char wndTitle[256];
    char wndClassName[256];

    Lazy(GetWindowTextA).forwarded_safe_cached()(hwnd, wndTitle, sizeof(wndTitle));
    Lazy(GetClassNameA).forwarded_safe_cached()(hwnd, wndClassName, sizeof(wndClassName));

    std::string windowTitle = wndTitle;
    std::string windowClassName = wndClassName;

    for (const auto& title : windowTitles) {
        if (windowTitle.find(title) != std::string::npos)
        {
            SendMessage(hwnd, WM_CLOSE, 0, 0);
            return TRUE;
        }
    }

    for (const auto& className : windowClassNames) {
        if (windowClassName.find(className) != std::string::npos)
        {
            SendMessage(hwnd, WM_CLOSE, 0, 0);
            return TRUE;
        }
    }

    return TRUE;
}


bool IsThreadRunning(HANDLE threadHandle)
{
    Lazy(ResumeThread).forwarded_safe_cached()(threadHandle);
    DWORD exitCode; if (Lazy(GetExitCodeThread).forwarded_safe_cached()(threadHandle, &exitCode) != 0) { return (exitCode == STILL_ACTIVE); }
    return false;
}

bool Check_Threads()
{
    if (thread_starter_called && thread1_started && thread2_started)
    {
        if (!Authorized || !tls_ran) { HandleAttack(); }
        if (Thread1 == 0 || Thread2 == 0 || time1 == 0 || time2 == 0) { HandleAttack(); }
        if (!IsThreadRunning(Thread1)) { Lazy(exit).forwarded_cached()(0x99); HandleAttack(); }
        if (!IsThreadRunning(Thread2)) { Lazy(exit).forwarded_cached()(0x99); HandleAttack(); }
        if (Lazy(GetTickCount64).forwarded_safe_cached()() - time1 > 4500) { HandleAttack(); }
        if (Lazy(GetTickCount64).forwarded_safe_cached()() - time2 > 4500) { HandleAttack(); }
        Lazy(ResumeThread).forwarded_safe_cached()(Thread1); Lazy(ResumeThread).forwarded_safe_cached()(Thread2);
    }

    return true;
}

void Check_Query_Info()
{
    HANDLE Process = INVALID_HANDLE_VALUE;
    PROCESS_BASIC_INFORMATION Info = { 0 };
    ULONG Length = 0;
    HMODULE Library = Lazy(LoadLibraryW).forwarded_safe_cached()(Encrypt(L"ntdll.dll"));
    CheckQueryInformationProcess NtQueryInformationProcess = NULL;
    NtQueryInformationProcess = (CheckQueryInformationProcess)Lazy(GetProcAddress).forwarded_safe_cached()(Library, Encrypt("NtQueryInformationProcess"));
    Process = Lazy(GetCurrentProcess).forwarded_safe_cached()();
    NTSTATUS Status = NtQueryInformationProcess(Process, ProcessBasicInformation, &Info, sizeof(Info), &Length);
    if (NT_SUCCESS(Status))
    {
        PPEB Peb = Info.PebBaseAddress;
        if (Peb)
        {
            if (Peb->BeingDebugged)
            {
                HandleAttack();
            }
        }
    }
}

bool driverdetect()
{
    const TCHAR* devices[] =
    {
        (Encrypt(_T("\\\\.\\kdstinker"))),
        (Encrypt(_T("\\\\.\\NiGgEr"))),
        (Encrypt(_T("\\\\.\\KsDumper"))),
        (Encrypt(_T("\\\\.\\HyperHideDrv")))
    };

    WORD iLength = sizeof(devices) / sizeof(devices[0]);
    for (int i = 0; i < iLength; i++)
    {
        HANDLE hFile = Lazy(CreateFileA).forwarded_safe_cached()(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        TCHAR msg[256] = _T("");
        if (hFile != INVALID_HANDLE_VALUE)
        {
            return true;
        }
    }

    return false;
}

void ModifySizeOfImage(HMODULE hModule)
{
    DWORD oldProtect;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + dosHeader->e_lfanew);
    Lazy(VirtualProtect).forwarded_safe_cached()(&ntHeaders->OptionalHeader.SizeOfImage, sizeof(DWORD), PAGE_READWRITE, &oldProtect);
    ntHeaders->OptionalHeader.SizeOfImage += 0x9999999999999999;
    Lazy(VirtualProtect).forwarded_safe_cached()(&ntHeaders->OptionalHeader.SizeOfImage, sizeof(DWORD), oldProtect, &oldProtect);
}

secure auto ProtectProcess()
{
    HANDLE handle = Lazy(GetCurrentProcess).forwarded_safe_cached()();
    DWORD aclSize = sizeof(ACL) + sizeof(ACCESS_DENIED_ACE) + GetSidLengthRequired(1);
    PACL pDacl = (PACL)new BYTE[aclSize];
    ZeroMemory(pDacl, aclSize);
    InitializeAcl(pDacl, aclSize, ACL_REVISION);
    PSID pSpecificSid = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&SIDAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSpecificSid);
    AddAccessDeniedAce(pDacl, ACL_REVISION, DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE, pSpecificSid);
    FreeSid(pSpecificSid);
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, pDacl, FALSE);
    PSID integritySid = NULL;
    SID_IDENTIFIER_AUTHORITY integrityAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    AllocateAndInitializeSid(&integrityAuthority,1,SECURITY_MANDATORY_MEDIUM_RID,0,0,0,0,0,0,0,&integritySid);
    DWORD saclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(integritySid);
    PACL pSacl = (PACL)new BYTE[saclSize];
    ZeroMemory(pSacl, saclSize);
    InitializeAcl(pSacl, saclSize, ACL_REVISION);
    AddAccessAllowedAce(pSacl, ACL_REVISION, PROCESS_ALL_ACCESS, integritySid);
    SetSecurityDescriptorSacl(&sd, TRUE, pSacl, FALSE);
    SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, &sd);
    delete[] pDacl;
    delete[] pSacl;
    FreeSid(integritySid);
    Lazy(DebugActiveProcessStop).forwarded_safe_cached()(Lazy(GetCurrentProcessId).forwarded_safe_cached()());
    if (fs::exists(Encrypt("certificate.crt")) || fs::exists(Encrypt("bypassed.exe")))
    {
        HandleAttack();
    }
}


bool LoadLibary_Check()
{
    std::string path = Encrypt("C:\\Windows\\System32\\calc.exe");
    const char* szBuffer = path.c_str();
    for (int i = 0; i < 200; ++i) // will spam mem map
    {
        Lazy(LoadLibraryA).forwarded_safe_cached()(szBuffer);
        Lazy(CreateFileA).forwarded_safe_cached()(szBuffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    }
}


secure auto CheckDebugger()
{
    Junkcode(); if (main_called) { if (!tls_ran) { HandleAttack(); } if (!Authorized) { HandleAttack(); } }
    if (!Check_Threads()) { HandleAttack(); } EnumWindows(Specter_Module, 0);
    for (int i = 0; i < 200; ++i) { int3bs(); } Junkcode();
    if (driverdetect()) { HandleAttack(); } Check_Query_Info(); CheckOperatingSystem();  DetectProcessHacker(); Junkcode();
}


void Specter_Thread01()
{
    OverwriteReturnAddress;
    Lazy(SetThreadExecutionState).forwarded_safe_cached()(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED); thread1_started = true;
    auto var_memory = Lazy(VirtualAlloc).forwarded_safe_cached()(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    for (;;)
    {
        time1 = Lazy(GetTickCount64).forwarded_safe_cached()();
        if (var_memory)
        {
            PSAPI_WORKING_SET_EX_INFORMATION var_information = { 0 };
            var_information.VirtualAddress = var_memory;
            auto var_is_valid = Lazy(K32QueryWorkingSetEx).forwarded_safe_cached()(Lazy(GetCurrentProcess).forwarded_safe_cached()(), &var_information, sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
            if (var_information.VirtualAttributes.Valid)
            {
                HandleAttack();
            }
        }
        CheckDebugger();
        Lazy(Sleep).forwarded_safe_cached()(1500);
    }
}

void Specter_Thread02()
{
    OverwriteReturnAddress;
    Lazy(SetThreadExecutionState).forwarded_safe_cached()(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED); thread2_started = true;
    for (;;)
    {
        time2 = Lazy(GetTickCount64).forwarded_safe_cached()();
        CheckDebugger();
        std::vector<void*> addys
       {
       (void*)Lazy(GetProcAddress).forwarded_safe_cached()(Lazy(GetModuleHandleW).forwarded_safe_cached()(((L"kernel32.dll"))), (Encrypt("GetModuleHandleA"))),		//
       (void*)Lazy(GetProcAddress).forwarded_safe_cached()(Lazy(GetModuleHandleW).forwarded_safe_cached()(((L"user32.dll"))), (Encrypt("FindWindowA"))),				//
       (void*)Lazy(GetProcAddress).forwarded_safe_cached()(Lazy(GetModuleHandleW).forwarded_safe_cached()(((L"Advapi32.dll"))), (Encrypt("RegOpenKeyA"))),			//
       (void*)Lazy(GetProcAddress).forwarded_safe_cached()(Lazy(GetModuleHandleW).forwarded_safe_cached()(((L"Advapi32.dll"))), (Encrypt("RegQueryValueExA"))),		//  THEMIDIE
       (void*)Lazy(GetProcAddress).forwarded_safe_cached()(Lazy(GetModuleHandleW).forwarded_safe_cached()(((L"ntdll.dll"))), (Encrypt("NtSetInformationThread"))),	//
       (void*)Lazy(GetProcAddress).forwarded_safe_cached()(Lazy(GetModuleHandleW).forwarded_safe_cached()(((L"ntdll.dll"))), (Encrypt("NtQueryVirtualMemory"))),		//
       (void*)Lazy(GetProcAddress).forwarded_safe_cached()(Lazy(GetModuleHandleW).forwarded_safe_cached()(((L"ws2_32.dll"))), (Encrypt("recv"))),
       (void*)Lazy(GetProcAddress).forwarded_safe_cached()(Lazy(GetModuleHandleW).forwarded_safe_cached()(((L"kernel32.dll"))), (Encrypt("GetVolumeInformationA"))),
       (void*)Lazy(GetProcAddress).forwarded_safe_cached()(Lazy(GetModuleHandleW).forwarded_safe_cached()(((L"kernel32.dll"))), (Encrypt("TerminateProcess"))),
       (void*)Lazy(GetProcAddress).forwarded_safe_cached()(Lazy(GetModuleHandleW).forwarded_safe_cached()(((L"ntdll.dll"))), (Encrypt("NtQuerySystemInformation"))),
       (void*)Lazy(GetProcAddress).forwarded_safe_cached()(Lazy(GetModuleHandleW).forwarded_safe_cached()(((L"kernalbase.dll"))),  (Encrypt("CreateThread"))),
       };

        for (auto address : addys) {
            if (address) {
                while (*(BYTE*)(address) == 0x90)
                {
                    HandleAttack();
                }
            }
        }

        Lazy(Sleep).forwarded_safe_cached()(2000);
    }
}


secure auto Initalize_Threads()
{
    Lazy(SetThreadExecutionState).forwarded_safe_cached()(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED); // kinda protects main thread
    Junkcode(); thread_starter_called = true;
    if (Authorized && tls_ran && main_called)
    {
        Thread1 = CALL(&Create_Hashed, nullptr, 0, (LPTHREAD_START_ROUTINE)&Specter_Thread01, nullptr, 0, nullptr);
        Thread2 = CALL(&Create_Hashed, nullptr, 0, (LPTHREAD_START_ROUTINE)&Specter_Thread02, nullptr, 0, nullptr);
        for (int i = 0; i < 50; ++i) { HANDLE Thread3 = CALL(&Create_Hashed, nullptr, 0, (LPTHREAD_START_ROUTINE)&Stop_Reversing_Retard, nullptr, 0, nullptr); HideThread(Thread3); Hide(Thread3); ChangePerms(Thread3); }
        Lazy(Sleep).forwarded_safe_cached()(500);
        if (Thread1 != 0 && Thread2 != 0 && Authorized)
        {
            if (thread1_started && thread2_started && Authorized && Check_Threads())
            {
                if (GetThreadId(Thread1) != 0 && GetThreadId(Thread2) != 0)
                {
                    Lazy(ResumeThread).forwarded_safe_cached()(Thread1); Lazy(ResumeThread).forwarded_safe_cached()(Thread2);
                    HideThread(Thread1); HideThread(Thread2);  Hide(Thread1); Hide(Thread2); ChangePerms(Thread1); ChangePerms(Thread2);
                }
                else
                {
                    Lazy(exit).forwarded_safe_cached()(0x5c);
                    __fastfail(0);
                }
            }
            else
            {
                Lazy(exit).forwarded_safe_cached()(0x5c);
                __fastfail(0);
            }
        }
        else
        {
            Lazy(exit).forwarded_safe_cached()(0x5c);
            __fastfail(0);
        }
    }
    else
    {
        Lazy(exit).forwarded_safe_cached()(0x5c);
        __fastfail(0);
    }
}

secure auto RemapProgramSections()
{
    ULONG_PTR ImageBase = (ULONG_PTR)Lazy(GetModuleHandleA).forwarded_safe_cached()(NULL);

    if (ImageBase)
    {
        __try
        {
            CALL(&RmpRemapImage, ImageBase);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            
        }
    }
}

bool ModifyTLSCallbackPtr(UINT64 NewTLSFunction)
{
    HMODULE hModule = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)dosHeader + dosHeader->e_lfanew);

    IMAGE_TLS_DIRECTORY* tlsDir = (IMAGE_TLS_DIRECTORY*)((BYTE*)hModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

    if (tlsDir == nullptr)
        return false;

    DWORD dwOldProt = 0;
    if (Lazy(VirtualProtect).forwarded_safe_cached()((LPVOID)tlsDir->AddressOfCallBacks, sizeof(UINT64), PAGE_EXECUTE_READWRITE, &dwOldProt))
    {
        __try
        {
            Lazy(memcpy).forwarded_safe_cached()((void*)(tlsDir->AddressOfCallBacks), (const void*)&NewTLSFunction, sizeof(UINT64));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    return false;
}

bool SelfDelete()
{
    WCHAR wcPath[MAX_PATH + 1];
    ZeroMemory(wcPath, sizeof(wcPath));
    Lazy(GetModuleFileNameW).forwarded_safe_cached()(NULL, wcPath, MAX_PATH);
    HANDLE hCurrent = Lazy(CreateFileW).forwarded_safe_cached()(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hCurrent == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    FILE_RENAME_INFO* fRename;
    LPWSTR lpwStream = const_cast<LPWSTR>(Encrypt((L":Specter.enc")));
    DWORD bslpwStream = (DWORD)(wcslen(lpwStream)) * sizeof(WCHAR);
    DWORD bsfRename = sizeof(FILE_RENAME_INFO) + bslpwStream;
    fRename = (FILE_RENAME_INFO*)malloc(bsfRename);
    if (fRename == nullptr)
    {
        Lazy(CloseHandle).forwarded_safe_cached()(hCurrent);
        return false;
    }
    ZeroMemory(fRename, bsfRename);
    fRename->FileNameLength = bslpwStream;
    Lazy(memcpy).forwarded_safe_cached()(fRename->FileName, lpwStream, bslpwStream);
    if (!SetFileInformationByHandle(hCurrent, FileRenameInfo, fRename, bsfRename))
    {
        free(fRename);
        Lazy(CloseHandle).forwarded_safe_cached()(hCurrent);
        return false;
    }
    free(fRename);
    Lazy(CloseHandle).forwarded_safe_cached()(hCurrent);
    hCurrent = Lazy(CreateFileW).forwarded_safe_cached()(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hCurrent == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    FILE_DISPOSITION_INFO fDelete;
    ZeroMemory(&fDelete, sizeof(fDelete));
    fDelete.DeleteFile = TRUE;
    if (!SetFileInformationByHandle(hCurrent, FileDispositionInfo, &fDelete, sizeof(fDelete)))
    {
        Lazy(CloseHandle).forwarded_safe_cached()(hCurrent);
        return false;
    }
    Lazy(CloseHandle).forwarded_safe_cached()(hCurrent);
    return true;
}

secure auto NoAccess()
{
    SYSTEM_INFO systemInfo;
    Lazy(GetSystemInfo).forwarded_safe_cached()(&systemInfo);
    size_t page_size = static_cast<size_t>(systemInfo.dwPageSize);
    void* memory = Lazy(VirtualAlloc).forwarded_safe_cached()(nullptr, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD oldProtect;
    Lazy(VirtualProtect).forwarded_safe_cached()(memory, page_size, PAGE_NOACCESS, &oldProtect);
}


class StartupTask  // x64 cannot identify this and wont auto bp
{
public:
    StartupTask()
    {
        CheckDebugger();
    }
};

static StartupTask startupTask;


void NTAPI __stdcall TLSCallback(PVOID DllHandle, DWORD dwReason, PVOID a)
{
    if (dwReason == DLL_PROCESS_ATTACH) // this shouldnt be called since the first tls handles it
    {
        Lazy(ExitThread).forwarded_safe_cached()(0x99);
    }

    if (dwReason == DLL_THREAD_ATTACH)  
    {
        OverwriteReturnAddress; CheckDebugger();
        if (block_threads)
        {
        }
    }
}

void NTAPI __stdcall TempTls(PVOID pHandle, DWORD dwReason, PVOID Reserved) 
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        NoStepie(); Lazy(DebugActiveProcessStop).forwarded_safe_cached()(Lazy(GetCurrentProcessId).forwarded_safe_cached()()); NoStepie();
        Junkcode(); ntdllcheck();
        Junkcode(); for (int i = 0; i < 200; ++i) { NoStepie(); int3bs(); }
        Junkcode(); if (CloseInvalidHandle()) { HandleAttack(); }
        if (RaiseDbgControl()) { HandleAttack(); }
        CheckDebugger(); tls_ran = true; ModifyTLSCallbackPtr((UINT64)&TLSCallback); Junkcode();
    }

    if (dwReason == DLL_THREAD_ATTACH) // shouldnt be reached but incase modifing fails we need this
    {
        OverwriteReturnAddress; CheckDebugger();
    }

}

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_func")
#endif
#ifdef _WIN64
#pragma const_seg(".CRT$XLF")
EXTERN_C const
#else
#pragma data_seg(".CRT$XLF")
EXTERN_C
#endif
PIMAGE_TLS_CALLBACK tls_callback_func = TempTls;
#ifdef _WIN64
#pragma const_seg()
#else
#pragma data_seg()
#endif //_WIN64