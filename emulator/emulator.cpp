#define _WIN32_WINNT 0x0400

#include <windows.h>
#include <stdio.h>
#include "logging.h"
#include "hook_helper.h"
#include "crypto.h"

#pragma comment(lib, "version.lib")

typedef unsigned int FT_STATUS;
typedef void* FT_HANDLE;

enum ReadRequestType
{
	InitHashXorByte,
	ReadBoxFw,
	ReadBoxSn,
	EmulateAfterReadCall,
	EmulateAfterReadCallIfEmpty,
	FullResponseEmulation,
	Unknown
};

static const bool g_EnableEmulation = true;

static ReadRequestType g_ReadRequestType = Unknown;

static BYTE g_ResponseBuffer[512];
static unsigned int g_ResponseBufferLength = 0;

// 10.3.50
// BC445320CCCCA2BE8E18FCB3
/*static const BYTE BOX_INFO[] = {
	0x1B, 0x1E, 0x78, 0x7F, 0xB0, 0x53, 0xA0, 0xE5, 0x10, 0xA1, 0xB2, 0xB1, 0x59, 0xFF, 0x66, 0x60,
	// box fw info
	0x41, 0x64, 0x76, 0x61, 0x6E, 0x63, 0x65, 0x42, 0x6F, 0x78, 0x20, 0x54, 0x75, 0x72, 0x62, 0x6F, 0x4C, 0x6F, 0x67, 0x69, 0x43, 0x6F, 0x72, 0x65, 0x20, 0x31, 0x30, 0x2E, 0x33, 0x2E, 0x35, 0x30,
	// maybe activation
	0x01, 0x0A, 0x55, 0x15,
	// reversed sn
	0xB3, 0xFC, 0x18, 0x8E, 0xBE, 0xA2, 0xCC, 0xCC, 0x20, 0x53, 0x44, 0xBC
};*/

// 11.0.10
// ECC390C4CE3BFD97E7F1493A
/*static const BYTE BOX_INFO[] = {
	0x1B, 0x1E, 0x78, 0x7F, 0xB0, 0x53, 0xA0, 0xE5, 0x10, 0xA1, 0xB2, 0xB1, 0x59, 0xFF, 0x66, 0x60,
	// box fw info
	0x41, 0x64, 0x76, 0x61, 0x6E, 0x63, 0x65, 0x42, 0x6F, 0x78, 0x20, 0x54, 0x75, 0x72, 0x62, 0x6F, 0x4C, 0x6F, 0x67, 0x69, 0x43, 0x6F, 0x72, 0x65, 0x20, 0x31, 0x31, 0x2E, 0x30, 0x2E, 0x31, 0x30,
	// maybe activation
	0x01, 0x0A, 0x55, 0x15,
	// reversed sn
	0x3A, 0x49, 0xF1, 0xE7, 0x97, 0xFD, 0x3B, 0xCE, 0xC4, 0x90, 0xC3, 0xEC
};*/

// 11.0.10
// F48B69F6E35B844B9198D9C9
/*static const BYTE BOX_INFO[] = {
	0x1B, 0x1E, 0x78, 0x7F, 0xB0, 0x53, 0xA0, 0xE5, 0x10, 0xA1, 0xB2, 0xB1, 0x59, 0xFF, 0x66, 0x60,
	// box fw info
	0x41, 0x64, 0x76, 0x61, 0x6E, 0x63, 0x65, 0x42, 0x6F, 0x78, 0x20, 0x54, 0x75, 0x72, 0x62, 0x6F, 0x4C, 0x6F, 0x67, 0x69, 0x43, 0x6F, 0x72, 0x65, 0x20, 0x31, 0x31, 0x2E, 0x30, 0x2E, 0x31, 0x30,
	// maybe activation
	0x01, 0x0A, 0x55, 0x15,
	// reversed sn
	0xC9, 0xD9, 0x98, 0x91, 0x4B, 0x84, 0x5B, 0xE3, 0xF6, 0x69, 0x8B, 0xF4
};*/

static const BYTE RSA_FILE_CONTENT[] = {
	0x83, 0x30, 0xA2, 0x87, 0x3B, 0x8A, 0xCE, 0xA9, 0xAD, 0x3D, 0x8D, 0x40,
	0x4A, 0xA2, 0x39, 0x7B, 0xAF, 0x45, 0x62, 0x80, 0xFF, 0x23, 0xB8, 0x40,
	0xA1, 0xBB, 0x9F, 0xE7, 0x90, 0x0F, 0xD9, 0x36, 0xF9, 0x77, 0x5A, 0xAB,
	0xBA, 0xFE, 0x2D, 0x8A, 0x12, 0x62, 0x3B, 0xBB, 0x4A, 0x74, 0x2F, 0x6D,
	0x51, 0x61, 0x10, 0x84, 0x02, 0x2E, 0x74, 0x90, 0xA3, 0x2D, 0x03, 0x19,
	0xCC, 0x27, 0x1F, 0x35, 0x00, 0x95, 0x75, 0x8D, 0x59, 0x37, 0xA4, 0xAD,
	0x5C, 0x38, 0x59, 0x87, 0x16, 0x08, 0x06, 0x94, 0xEE, 0x38, 0xD4, 0xB9,
	0x46, 0x70, 0x14, 0x00, 0x7E, 0x9C, 0x75, 0xF9, 0x00, 0x6D, 0x5F, 0x1E,
	0x8F, 0x23, 0x5A, 0x55, 0x7D, 0x9D, 0xDD, 0xB9, 0x4C, 0x3B, 0x33, 0x03,
	0x34, 0x31, 0x5A, 0x51, 0x35, 0x70, 0xA3, 0x58, 0x8A, 0x5B, 0xF4, 0xD8,
	0x4A, 0x0A, 0xE3, 0x9B, 0x47, 0x9F, 0x7B, 0x60
};

static const BYTE BOX_INFO_v10[] = {
	0x1B, 0x1E, 0x78, 0x7F, 0xB0, 0x53, 0xA0, 0xE5, 0x10, 0xA1, 0xB2, 0xB1, 0x59, 0xFF, 0x66, 0x60,
	// box fw info v10
	0x41, 0x64, 0x76, 0x61, 0x6E, 0x63, 0x65, 0x42, 0x6F, 0x78, 0x20, 0x54, 0x75, 0x72, 0x62, 0x6F, 0x4C, 0x6F, 0x67, 0x69, 0x43, 0x6F, 0x72, 0x65, 0x20, 0x31, 0x30, 0x2E, 0x33, 0x2E, 0x35, 0x30,
	// --
	0x01, 0x0A, 0x55, 0x15
};

static const BYTE BOX_INFO_v11[] = {
	0x1B, 0x1E, 0x78, 0x7F, 0xB0, 0x53, 0xA0, 0xE5, 0x10, 0xA1, 0xB2, 0xB1, 0x59, 0xFF, 0x66, 0x60,
	// box fw info v11
	0x41, 0x64, 0x76, 0x61, 0x6E, 0x63, 0x65, 0x42, 0x6F, 0x78, 0x20, 0x54, 0x75, 0x72, 0x62, 0x6F, 0x4C, 0x6F, 0x67, 0x69, 0x43, 0x6F, 0x72, 0x65, 0x20, 0x31, 0x31, 0x2E, 0x30, 0x2E, 0x31, 0x30,
	// --
	0x01, 0x0A, 0x55, 0x15
};

static const BYTE* BOX_INFO = BOX_INFO_v10;
static const DWORD BOX_INFO_LENGTH = sizeof(BOX_INFO_v10);
static const DWORD FULL_BOX_INFO_LENGTH = 64;

static BYTE BOX_FW[2];
static BYTE BOX_SN[12];

static BYTE g_BoxInfoHashXorByte;
static BYTE g_CurrentRequestXorByte;
static BYTE g_CurrentRequestIndex;

BYTE EncryptAuthResponseByte()
{
	BYTE index = g_CurrentRequestIndex;
	if (index >= 16 && index <= 47) // swap adjacent bytes for box fw version
	{
		index = index % 2 == 0
			? index + 1
			: index - 1;
	}

	return BOX_INFO[index] ^ g_CurrentRequestXorByte ^ g_BoxInfoHashXorByte;
}

BYTE DecryptAuthResponseByte(BYTE value)
{
	return value ^ g_CurrentRequestXorByte ^ g_BoxInfoHashXorByte;
}

BOOL IsFileExists(const char* path)
{
    DWORD attr = GetFileAttributesA(path);
    return (attr != 0xFFFFFFFF && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL GetCurrentVolumeSerialNumber(DWORD* outSerialNumber) {
    char exePath[MAX_PATH];
    char rootPath[MAX_PATH];

    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0)
	{
        return FALSE;
    }

	rootPath[0] = exePath[0];
	rootPath[1] = ':';
	rootPath[2] = '\\';
	rootPath[3] = '\0';
    return GetVolumeInformationA(rootPath, NULL, 0, outSerialNumber, NULL, NULL, NULL, 0);
}

void GenerateRsaFilePath(char* rsaPath, BYTE fwVersion1, BYTE fwVersion2)
{
	DWORD volumeSn;
	BYTE toHash[sizeof(volumeSn) + sizeof(BOX_SN) + 2];

	if (!GetCurrentVolumeSerialNumber(&volumeSn))
	{
		return;
	}

	toHash[0] = (BYTE)(volumeSn >> 24);
	toHash[1] = (BYTE)(volumeSn >> 16);
	toHash[2] = (BYTE)(volumeSn >> 8);
	toHash[3] = (BYTE)(volumeSn);
	memcpy(toHash + sizeof(DWORD), BOX_SN, sizeof(BOX_SN));
	toHash[sizeof(toHash) - 2] = fwVersion1;
	toHash[sizeof(toHash) - 1] = fwVersion2;

	BYTE output[20];
	CalculateSha1(toHash, sizeof(toHash), output);

	int offset = 0;
	char fileName[45];
	for (int i = 0; i < sizeof(output); i++)
	{
		offset += sprintf(fileName + offset, "%02X", output[i]);
	}
	
	sprintf(fileName + offset, ".rsa\0");

	GetModuleFileNameA(NULL, rsaPath, MAX_PATH);
    char* appExeNameStart = strrchr(rsaPath, '\\');
    if (appExeNameStart) *(appExeNameStart + 1) = '\0';
	strcat(rsaPath, fileName);
}

void CreateRsaFileIfNotExists()
{
	// rsa file is not needed for older app versions
	if (BOX_INFO != BOX_INFO_v11)
	{
		return;
	}

	char rsaPath[MAX_PATH];
	GenerateRsaFilePath(rsaPath, 0x64, 0x41);

	// some boxes have fw version starting like AdvancedBox... , some have ATF...
	// we are emulating AdvancedBox... , so copy file if user already has valid rsa file
	if (BOX_FW[0] != 0x64 || BOX_FW[1] != 0x41)
	{
		char originalRsaPath[MAX_PATH];
		GenerateRsaFilePath(originalRsaPath, BOX_FW[0], BOX_FW[1]);
		if (IsFileExists(originalRsaPath))
		{
			if (!IsFileExists(rsaPath)) CopyFileA(originalRsaPath, rsaPath, FALSE);
			return;
		}
	}

	if (IsFileExists(rsaPath))
	{
		return;
	}

	HANDLE hFile = CreateFileA(rsaPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
	{
        return;
    }

    DWORD bytesWritten = 0;
    BOOL result = WriteFile(hFile, RSA_FILE_CONTENT, sizeof(RSA_FILE_CONTENT), &bytesWritten, NULL);
    CloseHandle(hFile);
}

typedef FT_STATUS (__stdcall *FT_Read_t)(FT_HANDLE, void*, DWORD, unsigned int*);
FT_Read_t FT_ReadOrigFunc = NULL;

FT_STATUS __stdcall FT_Read_Hook(
	FT_HANDLE ftHandle,
	void* lpBuffer,
	DWORD dwBytesToRead,
	unsigned int* lpdwBytesReturned)
{
	if (!g_EnableEmulation)
	{
		FT_STATUS res = FT_ReadOrigFunc(ftHandle, lpBuffer, dwBytesToRead, lpdwBytesReturned);
		LogBufferToFile("FT_Read", lpBuffer, *lpdwBytesReturned);
		return res;
	}
	
	BYTE* buffer = (BYTE*)lpBuffer;

	if (g_ReadRequestType == FullResponseEmulation)
	{
		*lpdwBytesReturned = dwBytesToRead;
		memcpy(lpBuffer, g_ResponseBuffer, dwBytesToRead);
FT_READ_EMU_READ_EXIT:
		LogBufferToFile("[EMU] FT_Read", lpBuffer, *lpdwBytesReturned);
		g_ReadRequestType = Unknown;
		g_ResponseBufferLength = 0;
		return 0;
	}

	FT_STATUS ret = FT_ReadOrigFunc(ftHandle, lpBuffer, dwBytesToRead, lpdwBytesReturned);

	if (g_ReadRequestType == InitHashXorByte && *lpdwBytesReturned > 0)
	{
		g_BoxInfoHashXorByte = buffer[0];
	}
	else if (g_ReadRequestType == ReadBoxFw && *lpdwBytesReturned > 0)
	{
		// read first 2 bytes of fw string
		BOX_FW[g_CurrentRequestIndex - 16] = DecryptAuthResponseByte(buffer[1]);
		*lpdwBytesReturned = dwBytesToRead;
		memcpy(lpBuffer, g_ResponseBuffer, dwBytesToRead);
		goto FT_READ_EMU_READ_EXIT;
	}
	else if (g_ReadRequestType == ReadBoxSn && *lpdwBytesReturned > 0)
	{
		// box sn comes reversed in response
		BOX_SN[FULL_BOX_INFO_LENGTH - g_CurrentRequestIndex - 1] = DecryptAuthResponseByte(buffer[1]);
	}
	else if (g_ReadRequestType == EmulateAfterReadCall ||
			(g_ReadRequestType == EmulateAfterReadCallIfEmpty && *lpdwBytesReturned == 0))
	{
		*lpdwBytesReturned = g_ResponseBufferLength;
		memcpy(lpBuffer, g_ResponseBuffer, g_ResponseBufferLength);
		goto FT_READ_EMU_READ_EXIT;
	}

	g_ReadRequestType = Unknown;

	if (lpdwBytesReturned)
		LogBufferToFile("FT_Read", lpBuffer, *lpdwBytesReturned);

	return ret;
}

typedef FT_STATUS (__stdcall *FT_Write_t)(FT_HANDLE, void*, DWORD, unsigned int*);
FT_Write_t FT_WriteOrigFunc = NULL;

FT_STATUS __stdcall FT_Write_Hook(
	FT_HANDLE ftHandle,
	void* lpBuffer,
	DWORD dwBytesToWrite,
	unsigned int* lpdwBytesWritten)
{
	if (!g_EnableEmulation)
	{
		FT_STATUS res = FT_WriteOrigFunc(ftHandle, lpBuffer, dwBytesToWrite, lpdwBytesWritten);
		LogBufferToFile("FT_Write", lpBuffer, *lpdwBytesWritten);
		return res;
	}

	FT_STATUS ret = 0;
	BYTE* buffer = (BYTE*)lpBuffer;

	if (dwBytesToWrite == 16 && buffer[0] == 0x52)
	{
		g_ReadRequestType = InitHashXorByte;
		goto CALL_FT_WRITE;
	}
	if (dwBytesToWrite == 256 && buffer[0] == 0xF0) // read box info
	{
		g_CurrentRequestIndex = buffer[1];
		g_CurrentRequestXorByte = buffer[5];
		if (buffer[1] < BOX_INFO_LENGTH)
		{
			g_ReadRequestType = FullResponseEmulation;
			g_ResponseBuffer[0] = 0xF0;
			g_ResponseBuffer[1] = EncryptAuthResponseByte();
			g_ResponseBufferLength = 2;

			if (g_CurrentRequestIndex == 16 || g_CurrentRequestIndex == 17)
			{
				g_ReadRequestType = ReadBoxFw;
				goto CALL_FT_WRITE;
			}

			goto FT_WRITE_EMU_EXIT;
		}

		g_ReadRequestType = ReadBoxSn;
		goto CALL_FT_WRITE;
	}
	if (dwBytesToWrite == 1 && buffer[0] == 0x55) // activation check?
	{
		CreateRsaFileIfNotExists();
		g_ReadRequestType = EmulateAfterReadCall;
		g_ResponseBuffer[0] = 0x00;
		g_ResponseBufferLength = 1;
		goto CALL_FT_WRITE;
	}
	if (dwBytesToWrite == 1 && buffer[0] == 0x5E) // init rsa file check
	{
		g_ReadRequestType = EmulateAfterReadCallIfEmpty;
		memset(g_ResponseBuffer, 2, 8);
		for(int i = 0; i < 8; i++)
		{
			g_ResponseBuffer[i] = i;
		}
		g_ResponseBufferLength = 8;
		goto CALL_FT_WRITE;
	}
	if (dwBytesToWrite == 129 && buffer[0] == 0x56) // rsa file check
	{
		g_ReadRequestType = EmulateAfterReadCall;
		g_ResponseBuffer[0] = 0x00;
		g_ResponseBufferLength = 1;
		goto CALL_FT_WRITE;
	}

CALL_FT_WRITE:
	ret = FT_WriteOrigFunc(ftHandle, lpBuffer, dwBytesToWrite, lpdwBytesWritten);
	if (lpdwBytesWritten)
		LogBufferToFile("FT_Write", lpBuffer, *lpdwBytesWritten);

	return ret;

FT_WRITE_EMU_EXIT:
	*lpdwBytesWritten = dwBytesToWrite;
	LogBufferToFile("[EMU] FT_Write", lpBuffer, *lpdwBytesWritten);
	return ret;
}

static BOOL g_PatchedVmCheck = FALSE;
static DWORD g_VmPatchCount = 0;
static BOOL g_PatchedPrng = FALSE;

void PatchPrng()
{
	/*
	if (g_PatchedPrng) return;
	BYTE* randomFunc = (BYTE*)0x407464; // v12.70
	DWORD oldProt;
	if (VirtualProtect(randomFunc, 6, PAGE_EXECUTE_READWRITE, &oldProt))
	{
		if (randomFunc[0] == 0x53 &&
			randomFunc[1] == 0x31)
		{
			randomFunc[0] = 0xB8; // mov eax, 1
			randomFunc[1] = 0x01;
			randomFunc[2] = 0x00;
			randomFunc[3] = 0x00;
			randomFunc[4] = 0x00;
			randomFunc[5] = 0xC3; // ret
		}
		
		VirtualProtect(randomFunc, 6, oldProt, &oldProt);
		g_PatchedPrng = TRUE;
	}
	*/
}

// bypass IN instructions checks
void PatchVmCheck()
{
	if (g_PatchedVmCheck) return;

    BYTE* addr = (BYTE*)GetSectionAddressAfter(".idata");
    MEMORY_BASIC_INFORMATION memInfo;
    if (VirtualQuery(addr, &memInfo, sizeof(memInfo)) == 0)
	{
		return;
	}

	if (memInfo.Type == MEM_IMAGE &&
		(memInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
	{
		const BYTE pattern1[] = {0xB8,0x68,0x58,0x4D};
		const BYTE pattern2[] = {0xED,0x81,0xFB,0x68,0x58,0x4D,0x56,0x75};
		BYTE* patchAddr = addr;

		while (patchAddr + 15 < addr + memInfo.RegionSize)
		{
			if (memcmp(patchAddr, pattern1, sizeof(pattern1)) == 0 && *(patchAddr + 14) == 0xED)
			{
				BYTE patch1[] = {0xB8,0x00,0x00,0x00,0x00};
				memcpy(patchAddr, patch1, sizeof(patch1));
				memset(patchAddr + 14, 0x90, 1);
				FlushInstructionCache(GetCurrentProcess(), patchAddr, 15);
				g_VmPatchCount++;
			}

			if (memcmp(patchAddr, pattern2, sizeof(pattern2)) == 0)
			{
				BYTE patch2[] = {0xED,0x81,0xFB,0x11,0x11,0x11,0x11};
				memcpy(patchAddr, patch2, sizeof(patch2));
				FlushInstructionCache(GetCurrentProcess(), patchAddr, sizeof(patch2));
				g_VmPatchCount++;
			}

			patchAddr++;
			if (g_VmPatchCount == 2)
			{
				g_PatchedVmCheck = TRUE;
				return;
			}
		}
	}
}

typedef LONG (WINAPI *RegOpenKeyExA_t)(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);
typedef LONG (WINAPI *RegOpenKeyExW_t)(HKEY,LPCWSTR,DWORD,REGSAM,PHKEY);
RegOpenKeyExA_t RegOpenKeyExAOrigFunc = NULL;
RegOpenKeyExW_t RegOpenKeyExWOrigFunc = NULL;

LONG WINAPI RegOpenKeyExA_Hook(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	if (lpSubKey &&
		(stricmp(lpSubKey, "Software\\Wine") == 0 ||
		stricmp(lpSubKey, "HARDWARE\\ACPI\\DSDT\\VBOX__") == 0 ||
		stricmp(lpSubKey, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000") == 0 ||
		stricmp(lpSubKey, "Hardware\\Description\\System") == 0))
	{
		PatchVmCheck();
		PatchPrng();
		return ERROR_FILE_NOT_FOUND;
	}

	return RegOpenKeyExAOrigFunc(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LONG WINAPI RegOpenKeyExW_Hook(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	if (lpSubKey &&
		(_wcsicmp(lpSubKey, L"Software\\Wine") == 0 ||
		_wcsicmp(lpSubKey, L"HARDWARE\\ACPI\\DSDT\\VBOX__") == 0 ||
		_wcsicmp(lpSubKey, L"SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000") == 0 ||
		_wcsicmp(lpSubKey, L"Hardware\\Description\\System") == 0))
	{
		PatchVmCheck();
		PatchPrng();
		return ERROR_FILE_NOT_FOUND;
	}

	return RegOpenKeyExWOrigFunc(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

void __stdcall GetSystemTime_Hook(LPSYSTEMTIME t)
{
    t->wYear=2016; t->wMonth=9; t->wDayOfWeek=5; t->wDay=5;
    t->wHour=12; t->wMinute=12; t->wSecond=12; t->wMilliseconds=12;
}

void InstallHooks()
{
	static const char* BadSystemError = "Bad system. Failed to hook %s. Clean system or try on different Windows version.";

	FuncEntrySignature funcEntryBytes[] = {
        {{0x8B, 0xFF, 0x55, 0x8B, 0xFF}, 5},
        {{0xE9, 0xFF, 0xFF, 0xFF, 0xFF}, 5},
        {{0xB8, 0xFF, 0xFF, 0xFF, 0xFF}, 5}
    };

	HMODULE hModule = GetModuleHandleA("kernelbase.dll");
	BOOL hookedRegisry = FALSE;
	if (hModule)
	{
		HookFunctionWithFallbackSafe(hModule, "GetSystemTime", funcEntryBytes, sizeof(funcEntryBytes),
			NULL, (void*)GetSystemTime_Hook, FALSE);
		HookFunctionWithFallbackSafe(hModule, "RegOpenKeyExA", funcEntryBytes, sizeof(funcEntryBytes),
			(void**)&RegOpenKeyExAOrigFunc, (void*)RegOpenKeyExA_Hook, FALSE);
		hookedRegisry = HookFunctionWithFallbackSafe(hModule, "RegOpenKeyExW", funcEntryBytes, sizeof(funcEntryBytes),
			(void**)&RegOpenKeyExWOrigFunc, (void*)RegOpenKeyExW_Hook, FALSE);
	}

	// for win xp or 7
	if (!hookedRegisry)
	{
		hModule = LoadLibraryA("advapi32.dll");
		HookFunctionWithFallbackSafe(hModule, "RegOpenKeyExA", funcEntryBytes, sizeof(funcEntryBytes),
			(void**)&RegOpenKeyExAOrigFunc, (void*)RegOpenKeyExA_Hook, TRUE);
		HookFunctionWithFallbackSafe(hModule, "RegOpenKeyExW", funcEntryBytes, sizeof(funcEntryBytes),
			(void**)&RegOpenKeyExWOrigFunc, (void*)RegOpenKeyExW_Hook, TRUE);
	}

	hModule = GetModuleHandleA("kernel32.dll");
	if (hModule)
	{
		if (!hookedRegisry)
		{
			HookFunctionWithFallbackSafe(hModule, "RegOpenKeyExA", funcEntryBytes, sizeof(funcEntryBytes),
				(void**)&RegOpenKeyExAOrigFunc, (void*)RegOpenKeyExA_Hook, FALSE);
			HookFunctionWithFallbackSafe(hModule, "RegOpenKeyExW", funcEntryBytes, sizeof(funcEntryBytes),
				(void**)&RegOpenKeyExWOrigFunc, (void*)RegOpenKeyExW_Hook, FALSE);
		}

		HookFunctionWithFallbackSafe(hModule, "GetSystemTime", funcEntryBytes, sizeof(funcEntryBytes),
			NULL, (void*)GetSystemTime_Hook, FALSE);
	}

	hModule = LoadLibraryA("ftd2xx.dll");
	if (hModule)
	{
		EatHookFunction(hModule, "FT_Read", (void**)&FT_ReadOrigFunc, (void*)FT_Read_Hook, TRUE);
		EatHookFunction(hModule, "FT_Write", (void**)&FT_WriteOrigFunc, (void*)FT_Write_Hook, TRUE);
	}
}

void InitBuffers()
{
    char szModPath[MAX_PATH];
    DWORD dwHandle = 0;
    DWORD dwSize = 0;
    void* pBuffer = NULL;
    UINT uiSize = 0;
    VS_FIXEDFILEINFO* pFileInfo = NULL;

    if (GetModuleFileNameA(NULL, szModPath, MAX_PATH) == 0) return;

    dwSize = GetFileVersionInfoSizeA(szModPath, &dwHandle);
    if (dwSize == 0) return;

    pBuffer = malloc(dwSize);
    if (pBuffer == NULL) return;

    if (!GetFileVersionInfoA(szModPath, dwHandle, dwSize, pBuffer))
	{
        free(pBuffer);
        return;
    }

    if (!VerQueryValueA(pBuffer, "\\", (LPVOID*)&pFileInfo, &uiSize) || pFileInfo == NULL)
	{
        free(pBuffer);
		return;
    }

	WORD majorVersion = HIWORD(pFileInfo->dwFileVersionMS);
	if (majorVersion >= 11)
	{
		BOX_INFO = BOX_INFO_v11;
	}

    free(pBuffer);
}

BOOL APIENTRY DllMain(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		InitBuffers();
		InstallHooks();
	}

	return TRUE;
}