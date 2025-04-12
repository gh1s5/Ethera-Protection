#ifdef _WIN64
#define IS_64_BIT 1
#else
#define IS_64_BIT 0
#endif

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef struct _MYPEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID FastPebLockRoutine;
	PVOID FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID EventLogSection;
	PVOID EventLog;
	PVOID FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[0x2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	UCHAR Spare2[0x4];
	ULARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper; //PPS_POST_PREOCESS_INIT_ROUTINE?
	PVOID GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	ULONG OSBuildNumber;
	ULONG OSPlatformId;
	ULONG ImageSubSystem;
	ULONG ImageSubSystemMajorVersion;
	ULONG ImageSubSystemMinorVersion;
	ULONG GdiHandleBuffer[0x22];
	PVOID ProcessWindowStation;
} MYPEB, * PMYPEB;

#if IS_64_BIT
UINT64 GetPEBPointerAddress()
{
	typedef struct _TEB
	{
		PVOID Reserved1[12];
		PVOID ProcessEnvironmentBlock;
	} TEB, * PTEB;

	PTEB teb = (PTEB)__readgsqword(0x30);

	if (teb == NULL)
		return NULL;

	return (UINT64) & (teb->ProcessEnvironmentBlock);
}

PVOID GetPEBAddress()
{
	PTEB teb = (PTEB)__readgsqword(0x30);
	if (teb == NULL)
		return NULL;

	return teb->ProcessEnvironmentBlock;
}

void SetPEBAddress(UINT64 address)
{
	__try
	{
		UINT64 PEBPtrInTEB = GetPEBPointerAddress();
		*(UINT64*)PEBPtrInTEB = address;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return;
	}
}
#else
PVOID GetPEBAddress()
{
	PVOID pebAddress = 0;

	__asm
	{
		mov eax, fs: [0x18]
		mov eax, [eax + 0x30]
		mov pebAddress, eax
	}

	return pebAddress;
}

void SetPEBAddress(DWORD address)
{
	__asm
	{
		push ebx
		mov eax, fs: [0x18]
		mov eax, [eax + 0x30]
		mov ebx, address
		mov[eax], ebx
		pop ebx
	}
}
#endif

BYTE* CopyPEBBytes(unsigned int pebSize)
{
	LPVOID pebAddress = GetPEBAddress();

	BYTE* peb_bytes = new BYTE[sizeof(struct _MYPEB)];

	BOOL success = ReadProcessMemory(GetCurrentProcess(), pebAddress, peb_bytes, sizeof(struct _MYPEB), NULL);
	if (!success)
	{
		delete[] peb_bytes;
		return NULL;
	}

	return peb_bytes;
}

BYTE* SetNewPEB() //in this example, we are copying the original PEB to a byte array and then setting the pointer to the PEB to our byte array.
{
	BYTE* newPeb = CopyPEBBytes(sizeof(struct _MYPEB));

	if (newPeb != NULL)
	{
		SetPEBAddress((UINT64)newPeb);
	}

	return newPeb;
}


void RuntimeResetPeb()
{
	UINT64 pebAddr_Original = (UINT64)GetPEBAddress();

	BYTE* newPEBBytes = SetNewPEB();

	_MYPEB* ourPEB = (_MYPEB*)&newPEBBytes[0];

	UINT64 newPebAddr = (UINT64)GetPEBAddress();

	SetPEBAddress(pebAddr_Original);

	if ((UINT64)GetPEBAddress() == pebAddr_Original) { delete[] newPEBBytes; }

	pebAddr_Original = (UINT64)GetPEBAddress();
}
