#include "inject.h"
#include "ntdll.h"

PVOID g_KernelBase = 0;
ULONG g_KernelSize = 0;
PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT = 0;


NTSTATUS MySearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}


PVOID GetKernelBase(OUT PULONG pSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;

	// Already found
	if (g_KernelBase != NULL)
	{
		if (pSize)
			*pSize = g_KernelSize;
		return g_KernelBase;
	}

	RtlUnicodeStringInit(&routineName, L"NtOpenFile");

	checkPtr = MmGetSystemRoutineAddress(&routineName);
	if (checkPtr == NULL)
		return NULL;

	// Protect from UserMode AV
	status = wdk::ZwQuerySystemInformation(wdk::SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
	{
		debug_msg("%s: Invalid SystemModuleInformation size\n", __FUNCTION__);
		return NULL;
	}

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, MY_POOL_TAG);
	RtlZeroMemory(pMods, bytes);

	status = wdk::ZwQuerySystemInformation(wdk::SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (ULONG i = 0; i < pMods->NumberOfModules; i++)
		{
			// System routine is inside module
			if (checkPtr >= pMod[i].ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{
				g_KernelBase = pMod[i].ImageBase;
				g_KernelSize = pMod[i].ImageSize;
				if (pSize)
					*pSize = g_KernelSize;
				break;
			}
		}
	}

	if (pMods)
		ExFreePoolWithTag(pMods, MY_POOL_TAG);

	return g_KernelBase;
}

PSYSTEM_SERVICE_DESCRIPTOR_TABLE GetSSDTBase()
{
	PVOID ntosBase = GetKernelBase(NULL);

	// Already found
	if (g_SSDT != NULL)
		return g_SSDT;

	if (!ntosBase)
		return NULL;

	PIMAGE_NT_HEADERS pHdr = wdk::RtlImageNtHeader(ntosBase);
	PIMAGE_SECTION_HEADER pFirstSec = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++)
	{
		// Non-paged, non-discardable, readable sections
		// Probably still not fool-proof enough...
		if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
			pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
			!(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
			(*(PULONG)pSec->Name != 'TINI') &&
			(*(PULONG)pSec->Name != 'EGAP'))
		{
			PVOID pFound = NULL;

			// KiSystemServiceRepeat pattern
			UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
			NTSTATUS status = MySearchPattern(pattern, 0xCC, sizeof(pattern) - 1, (PUCHAR)ntosBase + pSec->VirtualAddress, pSec->Misc.VirtualSize, &pFound);
			if (NT_SUCCESS(status))
			{
				g_SSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
				debug_msg("%s: KeSystemServiceDescriptorTable = 0x%p\n", __FUNCTION__, g_SSDT);
				return g_SSDT;
			}
		}
	}

	return NULL;
}
PVOID GetSSDTEntry(IN ULONG index)
{
	ULONG size = 0;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = GetSSDTBase();
	PVOID pBase = GetKernelBase(&size);

	if (pSSDT && pBase)
	{
		// Index range check
		if (index > pSSDT->NumberOfServices)
			return NULL;

		return (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
	}

	return NULL;
}

NTSTATUS KernelInjectProcess(IN HANDLE ProcessID, IN PVOID bShell, IN SIZE_T dwShellSize)
{
	PEPROCESS EProcess = NULL;
	KAPC_STATE ApcState;
	NTSTATUS Status = STATUS_SUCCESS;

	if (ProcessID == NULL)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}

	Status = PsLookupProcessByProcessId(ProcessID, &EProcess);
	if (Status != STATUS_SUCCESS)
	{
		debug_msg("PsLookupProcessByProcessId failed\n");
		return Status;
	}

	KeStackAttachProcess((PRKPROCESS)EProcess, &ApcState);
	__try
	{
		PVOID pBuffer = NULL;
		Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &pBuffer, 0, &dwShellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NT_SUCCESS(Status))
		{
			memcpy(pBuffer, bShell, dwShellSize);
			debug_msg("pid: %d 地址：%llx 大小:%x\n", ProcessID, pBuffer, dwShellSize);
			ExecuteInNewThread(pBuffer, NULL, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, FALSE, NULL);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

		Status = STATUS_UNSUCCESSFUL;
	}

	KeUnstackDetachProcess(&ApcState);

	ObDereferenceObject(EProcess);
	return Status;
}

NTSTATUS ExecuteInNewThread(
	IN PVOID BaseAddress,
	IN PVOID Parameter,
	IN ULONG Flags,
	IN BOOLEAN Wait,
	OUT PNTSTATUS ExitStatus
)
{
	HANDLE ThreadHandle = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	//指定一个对象句柄的属性  句柄只能在内核模式访问。
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	//创建线程
	NTSTATUS Status = ZwCreateThreadEx(
		&ThreadHandle, THREAD_QUERY_LIMITED_INFORMATION, &ObjectAttributes,
		ZwCurrentProcess(), BaseAddress, Parameter, Flags,
		0, 0x1000, 0x100000, NULL
	);

	// 等待线程完成
	if (NT_SUCCESS(Status) && Wait != FALSE)
	{
		//60s
		LARGE_INTEGER Timeout = { 0 };
		Timeout.QuadPart = -(60ll * 10 * 1000 * 1000);

		Status = ZwWaitForSingleObject(ThreadHandle, TRUE, &Timeout);
		if (NT_SUCCESS(Status))
		{
			//查询线程退出码
			THREAD_BASIC_INFORMATION ThreadBasicInfo = { 0 };
			ULONG ReturnLength = 0;

			Status = wdk::ZwQueryInformationThread(ThreadHandle, ThreadBasicInformation, &ThreadBasicInfo, sizeof(ThreadBasicInfo), &ReturnLength);
			if (NT_SUCCESS(Status) && ExitStatus)
			{
				*ExitStatus = ThreadBasicInfo.ExitStatus;
			}
			else if (!NT_SUCCESS(Status))
			{
				debug_msg("%s: ZwQueryInformationThread failed with status 0x%X\n", __FUNCTION__, Status);
			}
		}
		else
			debug_msg("%s: ZwWaitForSingleObject failed with status 0x%X\n", __FUNCTION__, Status);
	}
	else
	{
		debug_msg("%s: ZwCreateThreadEx failed with status 0x%X\n", __FUNCTION__, Status);
	}
	if (ThreadHandle)
	{
		ZwClose(ThreadHandle);
	}
	return Status;
}

typedef NTSTATUS(NTAPI* fnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
	);

NTSTATUS
NTAPI
ZwCreateThreadEx(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
)
{
	NTSTATUS status = STATUS_SUCCESS;
	
	int NtCreateThdIndex = NTDLL::GetExportSsdtIndex("NtCreateThreadEx");
	debug_msg("%d\n",NtCreateThdIndex);
	fnNtCreateThreadEx NtCreateThreadEx = (fnNtCreateThreadEx)(ULONG_PTR)GetSSDTEntry(NtCreateThdIndex);
	if (NtCreateThreadEx)
	{
		//
		// If previous mode is UserMode, addresses passed into ZwCreateThreadEx must be in user-mode space
		// Switching to KernelMode allows usage of kernel-mode addresses
		//		
		UCHAR prevMode = wdk::PsGetCurrentThreadPreviousMode();
		wdk::PsSetThreadPreviousMode(PsGetCurrentThread(), KernelMode);

		status = NtCreateThreadEx(
			hThread, DesiredAccess, ObjectAttributes,
			ProcessHandle, lpStartAddress, lpParameter,
			Flags, StackZeroBits, SizeOfStackCommit,
			SizeOfStackReserve, AttributeList
		);

		wdk::PsSetThreadPreviousMode(PsGetCurrentThread(), prevMode);
	}
	else
	{
		debug_msg("ssdt func not found\n");
		status = STATUS_NOT_FOUND;
	}
	return status;
}