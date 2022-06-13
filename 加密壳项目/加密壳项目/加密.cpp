#include "iostream"
#include "windows.h"
#include "Pefunc.h"


int main()
{
	PCHAR src_FilePath = NULL;            //读取的硬盘源文件的路径名	
	DWORD src_FileSize = 0;               //读取的源文件大小
	PCHAR src_pFileBuffer = NULL;         //源文件缓存指针
	
	PCHAR shell_FilePath = NULL;          //读取的硬盘壳文件的路径名							
	DWORD shell_FileSize = 0;             //读取的壳文件大小
	PCHAR shell_pFileBuffer = NULL;       //壳文件缓存指针

	PCHAR shell_pNewFileBuffer = NULL;    //新的壳文件缓存指针
	DWORD shell_NewFileSize = 0;          //新的壳文件大小
	DWORD shell_NewSectionSize = 0;       //壳新增节区的大小
	
	PCHAR newFilePath = NULL;             //存入的硬盘文件的路径名

	//1.读取源程序成为源文件缓存
	src_FilePath = (PCHAR)"C:\\Users\\great\\Desktop\\源程序.exe";
	FileToBuffer(IN src_FilePath, OUT &src_FileSize, OUT &src_pFileBuffer);

	//2.对源文件缓存进行加密
	Encryption(src_pFileBuffer, src_FileSize);

	//3.读取壳程序成为壳文件缓存
	shell_FilePath = (PCHAR)"C:\\Users\\great\\Desktop\\壳程序.exe";
	FileToBuffer(IN shell_FilePath, OUT &shell_FileSize, OUT &shell_pFileBuffer);

	//4.对壳文件缓存新增一个节，并修改好PE头
	shell_NewSectionSize = src_FileSize;
	AddOneSectionHead(IN shell_pFileBuffer, IN shell_NewSectionSize, OUT &shell_NewFileSize, OUT &shell_pNewFileBuffer);

	//5.拷贝加密后的源文件缓存到壳文件缓存的新增节区
	//1.获取DOS头基址
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)shell_pNewFileBuffer;
	//2.获取NT头基址
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)shell_pNewFileBuffer + pDosHeader_Base->e_lfanew);
	//3.获取文件头基址
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.获取可选头基址	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.获取节表头数组基址
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);	
	//6.获取最后一个节的基址
	PCHAR LastSectionBase = PCHAR((PUCHAR)shell_pNewFileBuffer +pSectionHeaderGroup_Base[pFileHeader_Base->NumberOfSections - 1].PointerToRawData);
	//7.拷贝加密过的源缓存到新增的节
	memcpy(LastSectionBase, src_pFileBuffer, src_FileSize);

	//6.将修改后的壳文件缓存存盘为新的文件	
	PCHAR szFilePath = (PCHAR) "C:\\Users\\great\\Desktop\\加密过的程序.exe";
	BufferToFile(IN szFilePath, IN shell_NewFileSize, IN shell_pNewFileBuffer);

	system("pause");
	return 0;
}