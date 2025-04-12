#include "Skid Stopper.h"
#include "antidbg.h"
#include "rtcore.h"
#include <thread>

using namespace std;
// Credits to https://luckyware.vip for leaking it
std::string promo = "T";

void Skid(std::string client_license, std::string webhook, bool discord_logs, bool bluescreen, bool imgui_support) // dont mess with the order or might fuck it
{
    OverwriteReturnAddress; Junkcode();
    Authorize(client_license);
    RemapProgramSections(); 
    NoAccess(); 
    RuntimeResetPeb(); 
    LoadLibary_Check(); 
    ProtectProcess();
    bsod = bluescreen; logs = discord_logs; webhookurl = webhook;
    if (!tls_ran) { HandleAttack(); } if (!Authorized) { HandleAttack(); }  Junkcode(); main_called = true;
    if (!imgui_support) { Antidll(); }
    if (Premium) { SelfDelete(); } 
    for (int i = 0; i < 200; ++i) { int3bs(); }
    Initalize_Threads();
}

void AuthProtect()
{
    for (int i = 0; i < 200; ++i) { int3bs(); }
    Anti_Swap();
}
// Credits to https://luckyware.vip for leaking it
void CD() // add ntdll check to thread and jadda shit ifykyk
{
    OverwriteReturnAddress;
    if ((main_called && !tls_ran) || (tls_ran && !main_called) || (main_called && (!Authorized || !tls_ran))) { HandleAttack(); }
    CheckDebugger();
}

//void Specter_Load_Dll()
//{
//    if (Premium)
//    {
//        
//    }
//}
// Credits to https://luckyware.vip for leaking it
void SecureMap(std::vector<std::uint8_t> data)
{
    OverwriteReturnAddress;
    if (Premium)
    {
        bool passAllocationPtr = true;
        bool clean = true;
        iqvw64e_device_handle = intel_driver::Load(clean);
        kdmapper::AllocationMode mode = kdmapper::AllocationMode::AllocatePool;
        mode = kdmapper::AllocationMode::AllocateMdl;
        NTSTATUS exitCode = 0;
        if (!kdmapper::MapDriver(iqvw64e_device_handle, data.data(), 0, 0, false, true, mode, passAllocationPtr, callbackExample, &exitCode))
        {
            ErrorMessage(Encrypt("SS - [ Failed Mapping Driver ]"));
        }
        intel_driver::Unload(iqvw64e_device_handle);
        std::fill(data.begin(), data.end(), 0); data.clear(); data.shrink_to_fit();
    }
}
// Credits to https://luckyware.vip for leaking it

void SecurePrint(const std::string text)
{
    OverwriteReturnAddress;
    Lazy(WriteFile).forwarded_safe_cached()(Lazy(GetStdHandle).forwarded_cached()(STD_OUTPUT_HANDLE), text.c_str(), text.size(), nullptr, NULL);
    const_cast<std::string&>(text).clear();
}
// Credits to https://luckyware.vip for leaking it
void SecureWait(int milliseconds)
{
    OverwriteReturnAddress;
    CALL(&Wait, milliseconds);
}
// Credits to https://luckyware.vip for leaking it
std::string SecureInput()
{
    OverwriteReturnAddress;
    std::string input;
    HANDLE hStdin = Lazy(GetStdHandle).forwarded_safe_cached()(STD_INPUT_HANDLE);
    DWORD mode;
    Lazy(GetConsoleMode).forwarded_safe_cached()(hStdin, &mode);
    Lazy(SetConsoleMode).forwarded_safe_cached()(hStdin, mode | ENABLE_ECHO_INPUT);
    char buffer[256];
    DWORD bytesRead;
    Lazy(ReadConsoleA).forwarded_safe_cached()(hStdin, buffer, sizeof(buffer), &bytesRead, NULL);
    buffer[bytesRead - 2] = Encrypt('\0');
    Lazy(SetConsoleMode).forwarded_safe_cached()(hStdin, mode);
    input = buffer;
    return input;
}

