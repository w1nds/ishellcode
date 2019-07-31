/*
WIN64驱动开发模板
作者：W1nds
*/


extern "C"
{
#include <ntifs.h>
#include <ntintsafe.h>
#include <ntddk.h>
#include <intrin.h>
}



#include "GLOBAL.h"
#include "WDKExt/Wdk.h"
extern "C" DRIVER_INITIALIZE DriverEntry;

#define	DEVICE_NAME			L"\\Device\\ishellcode"
#define LINK_NAME			L"\\DosDevices\\ishellcode"
#define LINK_GLOBAL_NAME	L"\\DosDevices\\Global\\ishellcode"



#define IOCTL_IO_TEST		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)



VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING strLink;
	debug_msg("DriverUnload\n");
	
	//删除符号连接和设备
	RtlInitUnicodeString(&strLink, LINK_NAME);
	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObj->DeviceObject);
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	debug_msg("DispatchCreate\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	debug_msg("DispatchClose\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS UnSupportedIrpFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
	debug_msg("Unsupported Irp Function \n");
	return NtStatus;
}

typedef struct tagKeyBUF
{
	DWORD_PTR uMyPid;
	DWORD_PTR uTargetPid;
	DWORD_PTR pShellAddr;
	DWORD_PTR uShellSize;
}KEYBUF, *PKEYBUF;

NTSTATUS MyDDKWrite(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrP)
{

	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrP);
	ULONG ulWriteLength = stack->Parameters.Write.Length;

	ULONG mdl_length = MmGetMdlByteCount(pIrP->MdlAddress);                    //获取缓冲区的长度  
	PVOID  mdl_address = MmGetMdlVirtualAddress(pIrP->MdlAddress);     //获取缓冲区的虚拟地址  
	ULONG mdl_offset = MmGetMdlByteOffset(pIrP->MdlAddress);                   //返回缓冲区的偏移  

	debug_msg("mdl_length=%x ulWriteLength=%x\n", mdl_length, ulWriteLength);

	if (mdl_length != ulWriteLength)
	{
		//MDL的长度应该和读长度相等，否则该操作应该设为不成功  
		pIrP->IoStatus.Information = 0;
		status = STATUS_UNSUCCESSFUL;
	}
	else
	{
		//用那个MmGetSystemAddressForMdlSafe得到在内核模式下的影射  
		PVOID kernel_address = MmGetSystemAddressForMdlSafe(pIrP->MdlAddress, NormalPagePriority);
		if (mdl_length==sizeof(KEYBUF))
		{
			HANDLE ProcessID = (HANDLE)((PKEYBUF)kernel_address)->uMyPid;
			PVOID pShell = (PVOID)((PKEYBUF)kernel_address)->pShellAddr;
			DWORD_PTR dwSize = ((PKEYBUF)kernel_address)->uShellSize;
			HANDLE TargetProcessID = (HANDLE)((PKEYBUF)kernel_address)->uTargetPid;
			PVOID pShellBuf = ExAllocatePoolWithTag(PagedPool, dwSize, MY_POOL_TAG);

			//附加上去拷贝内存 或者直接用户层传递个shell文件的路径内核去读取
			PEPROCESS hProcess;
			PsLookupProcessByProcessId(ProcessID, &hProcess);
			KAPC_STATE apc_state;
			KeStackAttachProcess(hProcess, &apc_state);
			if (MmIsAddressValid(pShell))
			{
				//ProbeForRead((CONST PVOID)(PVOID)pUserBuf, uMemLoadSize, sizeof(CHAR));
				RtlCopyMemory((PVOID)pShellBuf, pShell, dwSize);
			}
			else
			{
				debug_msg("2:%llx %llx\n", ProcessID, pShell);
			}
			KeUnstackDetachProcess(&apc_state);


			KernelInjectProcess(TargetProcessID,pShellBuf,dwSize);
			if (pShellBuf)
				ExFreePoolWithTag(pShellBuf, MY_POOL_TAG);
		}
		pIrP->IoStatus.Information = ulWriteLength;
	}


	//完成IRP  
	pIrP->IoStatus.Status = status;                                                                    //设置完成状态  
	IoCompleteRequest(pIrP, IO_NO_INCREMENT);                                        //完成IRP  

	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{

	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	PDEVICE_OBJECT pDevObj;

	for (;;)
	{
		status = wdk::WdkInitSystem();
		if (!NT_SUCCESS(status))
		{
			debug_msg("WdkInitSystem failed\n");
			break;
		}
		break;
	}
	debug_msg("osver: %d \n", wdk::NtSystemVersion);
	if (!NT_SUCCESS(status))
	{
		DriverUnload(pDriverObj);
		return status;
	}

	//设置分发函数和卸载例程
	for (UINT32 uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
	{
		pDriverObj->MajorFunction[uiIndex] = UnSupportedIrpFunction;
	}
	pDriverObj->MajorFunction[IRP_MJ_WRITE] = MyDDKWrite;  
	pDriverObj->DriverUnload = DriverUnload;

	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))
		return status;
	//pDevObj->Flags |= DO_BUFFERED_IO;
	pDevObj->Flags |= DO_DIRECT_IO;
	pDevObj->Flags &= (~DO_DEVICE_INITIALIZING);
	
	RtlInitUnicodeString(&ustrLinkName, LINK_NAME);

	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}
	debug_msg("DriverEntry\n");

	return STATUS_SUCCESS;
}