#include "iostream"
#include "windows.h"
#include "Pe.h"

int main()
{
	//1.��ȡ���ܹ��ĳ����Ϊ�ļ�����
	PCHAR FilePath = NULL;            //��ȡ��Ӳ���ļ���·����	
	DWORD FileSize = 0;               //��ȡ���ļ���С
	PCHAR pFileBuffer = NULL;         //�ļ�����ָ��
	FilePath = (PCHAR)"C:\\Users\\great\\Desktop\\���ܹ��ĳ���.exe";
	FileToBuffer(IN FilePath, OUT &FileSize, OUT &pFileBuffer);

	//2.�����ļ���������һ����
	PCHAR pNewBuffer = NULL;  //������»����ָ��
	DWORD Newsize = 0;        //������»���Ĵ�С
	CopyLastSection(IN pFileBuffer, OUT &pNewBuffer, OUT & Newsize);
	
	//3.���н���
	Decryption(IN pNewBuffer, IN  Newsize);
	
	//4.���µĻ�������ɾ��񻺴�
	PCHAR pImageBuffer = NULL;    //����ľ��񻺴��ָ��
	FileBufferToImageBuffer(IN pNewBuffer, OUT &pImageBuffer);

	//5.�Թ���ʽ�����ǽ���
	//5.1 ��ȡ��ǰ���̵��ļ���·��
	char szCurrentPaths[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, szCurrentPaths, MAX_PATH);
	//5.2�Թ���ʽ����һ�����ܽ��̣��൱�ڽ���ǰ�������´�һ�Σ�˫��		
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	BOOL ret = CreateProcessA(NULL, szCurrentPaths, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (!ret)
	{
		printf("�������ܽ���ʧ��\n");
		return -1;
	}

	//6.��ȡ���ܽ��̵����̵߳�������
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &context);
	
	//7.ȡ�����ܽ��̵�ӳ��
	//7.1 ����ntdll.dll,���ntdllģ��ľ��
	HMODULE hModuleNt = GetModuleHandleA("ntdll.dll");
	if (hModuleNt == NULL)
	{
		printf("��ȡntdll���ʧ��\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	//7.2 ���庯��ָ��
	typedef DWORD(WINAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
	//7.3 ���NtUnmapViewOfSection�ĺ���ָ��
	pNtUnmapViewOfSection pUnmap= (pNtUnmapViewOfSection)GetProcAddress(hModuleNt, "NtUnmapViewOfSection");
	if (pUnmap == NULL)
	{
		printf("��ȡ NtUnmapViewOfSection ����ָ��ʧ��\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}
	//7.4 ��ȡ���ܽ��̵�ImageBase����PEB��ImageBaseAddress��ȡ������context.Ebx + 8��	
	DWORD OldImageBase;
	ReadProcessMemory(pi.hProcess, (LPCVOID)(context.Ebx + 8), &OldImageBase, sizeof(DWORD), NULL);
	//7.5 ���� NtUnmapViewOfSection ж�ؿ��ܽ���ӳ����ڴ澵��
	DWORD dwResult = pUnmap(pi.hProcess, (PVOID)OldImageBase);
	if (dwResult)
	{
		printf("ȡ����ӳ��ʧ��\n");
		return -1;
	}

	//8.�ڿ��ܽ����������ڴ棬�����񻺴渴�ƽ���
	//8.1��ȡ���񻺴��е�DOSͷ��ַ
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pImageBuffer;
	//8.2.��ȡ���񻺴��е�NTͷ��ַ
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((DWORD)pImageBuffer + pDosHeader_Base->e_lfanew);
	//8.3.��ȡ���񻺴��е��ļ�ͷ��ַ
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader_Base + 4);
	//8.4.��ȡ���񻺴��еĿ�ѡͷ��ַ	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((DWORD)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));			
	//8.5��ȡ���񻺴����趨�ľ����С
	DWORD ImageSize = pOptionHeader_Base->SizeOfImage;
	DWORD ImageBase = pOptionHeader_Base->ImageBase;
	//8.6�����ڴ� 
	LPVOID pImageBase = VirtualAllocEx(pi.hProcess, (LPVOID)ImageBase, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if ((DWORD)pImageBase != ImageBase)
	{
		printf("VirtualAllocEx ������: 0x%X\n", GetLastError());       
		printf("���뵽��ָ��: 0x%X, �����ĵ�ַ: 0x%X\n", (DWORD)pImageBase, ImageBase);
		TerminateThread(pi.hThread, 0);
		return -1;
	}	
	//8.7�����񻺴�д�뵽�ǽ�������������ڴ���
	if (0 == WriteProcessMemory(pi.hProcess, (LPVOID)pImageBase, pImageBuffer, ImageSize, NULL))
	{
		printf("д��Դ�����ڴ澵��ʧ��\n");
		TerminateThread(pi.hThread, 0);
		return -1;
	}

	//9. ����PEB��ImageBaseAddress	
	WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 8), &pImageBase, 4, NULL);

	//10.�������̵߳��������е�EAX	
	context.Eax = (DWORD)pImageBase + pOptionHeader_Base->AddressOfEntryPoint;
	context.ContextFlags = CONTEXT_FULL;
	SetThreadContext(pi.hThread, &context);
	
	//11.�ָ�����Ŀ��ܽ��̵����߳�
	ResumeThread(pi.hThread);

	//12.�ͷ�������ļ������뾵�񻺴�
	free(pNewBuffer);
	free(pImageBuffer);
	
	//system("pause");
	return 0;
}