#include "iostream"
#include "windows.h"
#include "Pe.h"

int main()
{
	//1.读取加密过的程序成为文件缓存
	PCHAR FilePath = NULL;            //读取的硬盘文件的路径名	
	DWORD FileSize = 0;               //读取的文件大小
	PCHAR pFileBuffer = NULL;         //文件缓存指针
	FilePath = (PCHAR)"C:\\Users\\great\\Desktop\\加密过的程序.exe";
	FileToBuffer(IN FilePath, OUT &FileSize, OUT &pFileBuffer);

	//2.拷贝文件缓存的最后一个节
	PCHAR pNewBuffer = NULL;  //申请的新缓存的指针
	DWORD Newsize = 0;        //申请的新缓存的大小
	CopyLastSection(IN pFileBuffer, OUT &pNewBuffer, OUT & Newsize);
	
	//3.进行解密
	Decryption(IN pNewBuffer, IN  Newsize);
	
	//4.将新的缓存拉伸成镜像缓存
	PCHAR pImageBuffer = NULL;    //申请的镜像缓存的指针
	FileBufferToImageBuffer(IN pNewBuffer, OUT &pImageBuffer);

	//5.以挂起方式创建壳进程
	//5.1 获取当前进程的文件名路径
	char szCurrentPaths[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, szCurrentPaths, MAX_PATH);
	//5.2以挂起方式创建一个傀儡进程，相当于将当前进程重新打开一次，双开		
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	BOOL ret = CreateProcessA(NULL, szCurrentPaths, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (!ret)
	{
		printf("创建傀儡进程失败\n");
		return -1;
	}

	//6.获取傀儡进程的主线程的上下文
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &context);
	
	//7.取消傀儡进程的映射
	//7.1 加载ntdll.dll,获得ntdll模块的句柄
	HMODULE hModuleNt = GetModuleHandleA("ntdll.dll");
	if (hModuleNt == NULL)
	{
		printf("获取ntdll句柄失败\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	//7.2 定义函数指针
	typedef DWORD(WINAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
	//7.3 获得NtUnmapViewOfSection的函数指针
	pNtUnmapViewOfSection pUnmap= (pNtUnmapViewOfSection)GetProcAddress(hModuleNt, "NtUnmapViewOfSection");
	if (pUnmap == NULL)
	{
		printf("获取 NtUnmapViewOfSection 函数指针失败\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	//7.4 获取傀儡进程的ImageBase，从PEB的ImageBaseAddress获取（即：context.Ebx + 8）	
	DWORD OldImageBase;
	ReadProcessMemory(pi.hProcess, (LPCVOID)(context.Ebx + 8), &OldImageBase, sizeof(DWORD), NULL);
	//7.5 调用 NtUnmapViewOfSection 卸载傀儡进程映射的内存镜像
	DWORD dwResult = pUnmap(pi.hProcess, (PVOID)OldImageBase);
	if (dwResult)
	{
		printf("取消壳映射失败\n");
		return -1;
	}

	//8.在傀儡进程内申请内存，将镜像缓存复制进来
	//8.1获取镜像缓存中的DOS头基址
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pImageBuffer;
	//8.2.获取镜像缓存中的NT头基址
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((DWORD)pImageBuffer + pDosHeader_Base->e_lfanew);
	//8.3.获取镜像缓存中的文件头基址
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader_Base + 4);
	//8.4.获取镜像缓存中的可选头基址	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));			
	//8.5获取镜像缓存中设定的镜像大小
	DWORD ImageSize = pOptionHeader_Base->SizeOfImage;
	DWORD ImageBase = pOptionHeader_Base->ImageBase;
	//8.6申请内存 
	LPVOID pImageBase = VirtualAllocEx(pi.hProcess, (LPVOID)ImageBase, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if ((DWORD)pImageBase != ImageBase)
	{
		printf("VirtualAllocEx 错误码: 0x%X\n", GetLastError());       
		printf("申请到的指针: 0x%X, 期望的地址: 0x%X\n", (DWORD)pImageBase, ImageBase);
		TerminateThread(pi.hThread, 0);
		return -1;
	}	
	//8.7将镜像缓存写入到壳进程中新申请的内存里
	if (0 == WriteProcessMemory(pi.hProcess, (LPVOID)pImageBase, pImageBuffer, ImageSize, NULL))
	{
		printf("写入源程序内存镜像失败\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}

	//9. 修正PEB的ImageBaseAddress	
	WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 8), &pImageBase, 4, NULL);

	//10.修正主线程的上下文中的EAX	
	context.Eax = (DWORD)pImageBase + pOptionHeader_Base->AddressOfEntryPoint;
	context.ContextFlags = CONTEXT_FULL;
	SetThreadContext(pi.hThread, &context);
	
	//11.恢复挂起的傀儡进程的主线程
	ResumeThread(pi.hThread);

	//12.释放申请的文件缓存与镜像缓存
	free(pNewBuffer);
	free(pImageBuffer);
	
	//system("pause");
	return 0;
}