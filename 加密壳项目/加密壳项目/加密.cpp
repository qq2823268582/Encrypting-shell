#include "iostream"
#include "windows.h"
#include "Pefunc.h"


int main()
{
	PCHAR src_FilePath = NULL;            //��ȡ��Ӳ��Դ�ļ���·����	
	DWORD src_FileSize = 0;               //��ȡ��Դ�ļ���С
	PCHAR src_pFileBuffer = NULL;         //Դ�ļ�����ָ��
	
	PCHAR shell_FilePath = NULL;          //��ȡ��Ӳ�̿��ļ���·����							
	DWORD shell_FileSize = 0;             //��ȡ�Ŀ��ļ���С
	PCHAR shell_pFileBuffer = NULL;       //���ļ�����ָ��

	PCHAR shell_pNewFileBuffer = NULL;    //�µĿ��ļ�����ָ��
	DWORD shell_NewFileSize = 0;          //�µĿ��ļ���С
	DWORD shell_NewSectionSize = 0;       //�����������Ĵ�С
	
	PCHAR newFilePath = NULL;             //�����Ӳ���ļ���·����

	//1.��ȡԴ�����ΪԴ�ļ�����
	src_FilePath = (PCHAR)"C:\\Users\\great\\Desktop\\Դ����.exe";
	FileToBuffer(IN src_FilePath, OUT &src_FileSize, OUT &src_pFileBuffer);

	//2.��Դ�ļ�������м���
	Encryption(src_pFileBuffer, src_FileSize);

	//3.��ȡ�ǳ����Ϊ���ļ�����
	shell_FilePath = (PCHAR)"C:\\Users\\great\\Desktop\\�ǳ���.exe";
	FileToBuffer(IN shell_FilePath, OUT &shell_FileSize, OUT &shell_pFileBuffer);

	//4.�Կ��ļ���������һ���ڣ����޸ĺ�PEͷ
	shell_NewSectionSize = src_FileSize;
	AddOneSectionHead(IN shell_pFileBuffer, IN shell_NewSectionSize, OUT &shell_NewFileSize, OUT &shell_pNewFileBuffer);

	//5.�������ܺ��Դ�ļ����浽���ļ��������������
	//1.��ȡDOSͷ��ַ
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)shell_pNewFileBuffer;
	//2.��ȡNTͷ��ַ
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)shell_pNewFileBuffer + pDosHeader_Base->e_lfanew);
	//3.��ȡ�ļ�ͷ��ַ
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.��ȡ��ѡͷ��ַ	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.��ȡ�ڱ�ͷ�����ַ
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);	
	//6.��ȡ���һ���ڵĻ�ַ
	PCHAR LastSectionBase = PCHAR((PUCHAR)shell_pNewFileBuffer +pSectionHeaderGroup_Base[pFileHeader_Base->NumberOfSections - 1].PointerToRawData);
	//7.�������ܹ���Դ���浽�����Ľ�
	memcpy(LastSectionBase, src_pFileBuffer, src_FileSize);

	//6.���޸ĺ�Ŀ��ļ��������Ϊ�µ��ļ�	
	PCHAR szFilePath = (PCHAR) "C:\\Users\\great\\Desktop\\���ܹ��ĳ���.exe";
	BufferToFile(IN szFilePath, IN shell_NewFileSize, IN shell_pNewFileBuffer);

	system("pause");
	return 0;
}