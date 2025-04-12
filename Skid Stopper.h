#include <string>
#include <vector>
#pragma comment(lib, "Shlwapi.lib")
// pls note you can not rename exe after launch or some features may not work
// discord logs wont work unless you have a premium plan

void Skid(std::string client_license, std::string webhook, bool discord_logs, bool bluescreen, bool imgui_support);
void AuthProtect(); //stops auth swap
void CD(); //Check Debugger
void SecurePrint(const std::string text);
void SecureWait(int milliseconds);
std::string SecureInput(); // example string License = Specter_Getinput();

// premium

void SecureMap(std::vector<std::uint8_t> data); // ud mapper works on win10 and win11 + securly wipes data after preventing leaking driver bytes in memory