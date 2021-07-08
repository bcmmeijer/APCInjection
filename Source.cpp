#include <iostream>
#include <vector>

#include <Windows.h>
#include <TlHelp32.h>

DWORD get_pid(const char* process) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) 
		return 0;

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);

	if (!Process32First(snapshot, &pe)) {
		CloseHandle(snapshot);
		return 0;
	}

	DWORD pid = 0;
	do {
		if (!strcmp(pe.szExeFile, process)) {
			pid = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(snapshot, &pe));

	CloseHandle(snapshot);
	return pid;
}

bool get_threads(DWORD pid, std::vector<DWORD>& outthreads) {
	outthreads.clear();

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
	if (snapshot == INVALID_HANDLE_VALUE) 
		return false;

	THREADENTRY32 te;
	te.dwSize = sizeof(te);

	if (!Thread32First(snapshot, &te)) {
		CloseHandle(snapshot);
		return false;
	}

	do {
		outthreads.emplace_back(te.th32ThreadID);
	} while (Thread32Next(snapshot, &te));

	CloseHandle(snapshot);
	return true;
}

int main(int argc, const char** argv) {
	
	if (argc < 3) return 1;

	const char* process = argv[1];
	const char* dllpath = argv[2];

	DWORD pid = get_pid(process);
	if (!pid) return 1;

	std::vector<DWORD> threads;
	if (!get_threads(pid, threads))
		return 1;

	HANDLE hproc = OpenProcess(PROCESS_VM_OPERATION, false, pid);
	if (hproc == INVALID_HANDLE_VALUE)
		return 1;

	size_t dllpathlen = strlen(dllpath) + 1;
	void* remote_buf = VirtualAllocEx(hproc, nullptr, dllpathlen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remote_buf) {
		CloseHandle(hproc);
		return 1;
	}

	if (!WriteProcessMemory(hproc, remote_buf, dllpath, dllpathlen, nullptr)) {
		VirtualFreeEx(hproc, remote_buf, 0, MEM_RELEASE | MEM_FREE);
		CloseHandle(hproc);
		return 1;
	}

	for (auto& tid : threads) {

		HANDLE hthread = OpenThread(THREAD_SET_CONTEXT, false, tid);
		if (!hthread) {
			VirtualFreeEx(hproc, remote_buf, 0, MEM_RELEASE | MEM_FREE);
			CloseHandle(hproc);
			return 1;
		}

		QueueUserAPC((PAPCFUNC)LoadLibraryA, hthread, (ULONG_PTR)remote_buf);
		CloseHandle(hthread);
	}
	
	return 0;
}
