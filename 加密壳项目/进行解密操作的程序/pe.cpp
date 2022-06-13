# define _CRT_SECURE_NO_WARNINGS
#include   "iostream"
# include  "windows.h"
#include   <TlHelp32.h>
#include   "Pe.h"


//【封装函数】Align:对齐计算函数
//【参数1】size：对齐前的大小
//【参数2】ALIGN_BASE：对齐的粒度
//【返回值】DWORD：对齐后的大小
DWORD Align(IN DWORD size, IN DWORD ALIGN_BASE)
{
	if (size % ALIGN_BASE != 0)
	{
		size = (size / ALIGN_BASE + 1) * ALIGN_BASE;
	}
	return size;
}


//【封装函数】FileToBuffer：读取硬盘文件到文件缓存
//【参数1】FilePath：读取的硬盘文件的路径名  //一级指针
//【参数2】FileSize：指向“读取的文件大小”的指针  //一级指针
//【参数3】pFileBuffer:指向“文件缓存指针”的指针  //二级指针
//【返回值】BOOL ：成功返回TRUE，失败返回FALSE
BOOL FileToBuffer(IN PCHAR FilePath, OUT DWORD* FileSize, OUT PCHAR* pFileBuffer)
{
	//1.打开文件名
	FILE* pFile = fopen(FilePath, "rb");
	if (!pFile)
	{
		printf("打开文件失败！ \r\n");
		return FALSE;
	}

	//2.获取文件大小
	fseek(pFile, 0, SEEK_END);
	DWORD Size = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	//3.分配内存空间
	*pFileBuffer = (PCHAR)malloc(Size);
	if (!*pFileBuffer)
	{
		printf("分配空间失败!");
		fclose(pFile);
		return FALSE;
	}

	//4.读取文件到文件缓存中
	if (!fread(*pFileBuffer, Size, 1, pFile))
	{
		printf("读取数据失败!");
		free(*pFileBuffer);
		fclose(pFile);
		return FALSE;
	}

	//5.关闭文件名
	fclose(pFile);

	*FileSize = Size;

	return TRUE;
}


//【封装函数】RvaToFoa:将Rva转换为Foa
//【参数1】pFileBuffer:文件缓存指针 //一级指针
//【参数2】RVA:相对内存偏移 
//【返回值】DWORD：相对文件偏移FOA
DWORD RvaToFoa(IN PCHAR pFileBuffer, IN DWORD RVA)
{
	//-------------------------------1.定位PE结构各种基址------------------------------------	
	//1.获取DOS头基址
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	//2.获取NT头基址
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	//3.获取文件头基址
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.获取可选头基址	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.获取节表头数组基址
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);

	//--------------------------2.当RVA在文件头内时----------------------------------
	if (RVA < pOptionHeader_Base->SizeOfHeaders)
	{
		return RVA;
	}

	//--------------------------3.当RVA在节区内时---------------------------------------------
	for (int i = 0; i < pFileHeader_Base->NumberOfSections; i++)
	{
		//1.获取节头偏移（RVA类型）
		DWORD SectionHead_Offset = pSectionHeaderGroup_Base[i].VirtualAddress;
		//2.获取节真实大小
		DWORD Section_Size = pSectionHeaderGroup_Base[i].Misc.VirtualSize;
		//3.获取节尾偏移（RVA类型）
		DWORD SectionTail_Offset = SectionHead_Offset + Section_Size;
		//4.判断RVA是否在节区内（SectionHead_Offset <= RVA< SectionTail_Offset）
		if (SectionHead_Offset <= RVA && RVA < SectionTail_Offset)
		{
			DWORD FOA = pSectionHeaderGroup_Base[i].PointerToRawData + (RVA - SectionHead_Offset);
			return FOA;
		}
	}
	//--------------------------4.其它情况：RVA不在有效范围----------------------------------
	printf("RVA不在有效范围，转换失败！\n");
	return 0;
}


//【封装函数】FoaToRva:将Foa转换为Rva
//【参数1】pFileBuffer:文件缓存指针 //一级指针
//【参数2】FOA:文件相对偏移 
//【返回值】DWORD：内存相对偏移RVA  
DWORD FoaToRva(IN PCHAR pFileBuffer, IN DWORD FOA)
{
	//-------------------------------1.定位PE结构各种基址------------------------------------	
	//1.获取DOS头基址
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	//2.获取NT头基址
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	//3.获取文件头基址
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.获取可选头基址	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.获取节表头数组基址
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);

	//--------------------------2.当FOA在文件头内时----------------------------------
	if (FOA < pOptionHeader_Base->SizeOfHeaders)
	{
		return FOA;
	}

	//--------------------------3.当FOA在节区内时---------------------------------------------
	for (int i = 0; i < pFileHeader_Base->NumberOfSections; i++)
	{
		//1.获取节头偏移（FOA类型）
		DWORD SectionHead_Offset = pSectionHeaderGroup_Base[i].PointerToRawData;
		//2.获取节真实大小
		DWORD Section_Size = pSectionHeaderGroup_Base[i].Misc.VirtualSize;
		//3.获取节尾偏移（FOA类型）
		DWORD SectionTail_Offset = SectionHead_Offset + Section_Size;
		//4.判断RVA是否在节区内（SectionHead_Offset <= RVA< SectionTail_Offset）
		if (SectionHead_Offset <= FOA && FOA < SectionTail_Offset)
		{
			DWORD RVA = pSectionHeaderGroup_Base[i].VirtualAddress + (FOA - SectionHead_Offset);
			return RVA;
		}
	}
	//--------------------------4.其它情况：FOA不在有效范围----------------------------------
	printf("FOA不在有效范围,转换失败！\n");
	return -3;
}


//【封装函数】AddOneSectionHead：新增节表头并修改整个PE头的属性
//【参数1】pFileBuffer:文件缓存指针 //一级指针
//【参数2】NewSectionSize ：新增节的大小（自定义大小）
//【参数3】pNewFileSize：指向“新的文件大小”的指针 //一级指针
//【参数4】pNewFileBuffer ：指向“新的文件缓存指针”的指针  //二级指针
//【返回值】BOOL ：成功返回TRUE，失败返回FALSE
BOOL AddOneSectionHead(IN PCHAR pFileBuffer, IN DWORD NewSectionSize, OUT DWORD* NewFileSize, OUT PCHAR* pNewFileBuffer)
{
	//-------------------------------1.定位PE结构各种基址------------------------------------	
	//1.获取DOS头基址
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	//2.获取NT头基址
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	//3.获取文件头基址
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.获取可选头基址	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.获取节表头数组基址
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);

	//-------------------------------步骤2：计算节表头数组末尾到节区之间的空白大小-------------------------------------
	//1.获得节的数量
	DWORD numberOfSection = pFileHeader_Base->NumberOfSections;
	//2.获取节表头数组末尾的基址
	PVOID pSectionHeaderGroup_Tail = &pSectionHeaderGroup_Base[numberOfSection];
	//3.获取节表头数组末尾的偏移
	DWORD pSectionHeaderGroup_Tail_Offset = (DWORD)pSectionHeaderGroup_Tail - (DWORD)pFileBuffer;
	//4.获取节表数组末尾到节区之间的空白大小(空白大小 = 整个头的大小 -节表数组末尾的偏移） 
	DWORD WhiteSize = pOptionHeader_Base->SizeOfHeaders - pSectionHeaderGroup_Tail_Offset;
	//5.如果空白大小不足80，那么抹除DOS存根数据并将NT头,节表数组整理向上移动，并修正e_lfanew
	if (WhiteSize < 80)
	{
		//5.1 抹除DOS存根数据（抹除的大小 = PE标志的偏移 -DOS头大小偏移）
		PVOID pDosSub_Base = PVOID((DWORD)pFileBuffer + sizeof(IMAGE_DOS_HEADER));
		memset(pDosSub_Base, 0, pDosHeader_Base->e_lfanew - sizeof(IMAGE_DOS_HEADER));
		//5.2 计算NT头加上节表数组的大小之和（NT头大小直接用sizeof结构体来求，节表数组的大小用单个节表大小乘以节表数量）
		DWORD dwMoveSize = sizeof(IMAGE_NT_HEADERS) + pFileHeader_Base->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;
		//5.3 申请缓冲区内存，将要移动的NT头加上节表数组复制到缓冲区
		PVOID pTemp1 = (PUCHAR)malloc(dwMoveSize);       //申请缓冲区内存
		if (!pTemp1)
		{
			printf("申请缓冲区失败!");
			free(pFileBuffer);
			return FALSE;
		}
		memset(pTemp1, 0, dwMoveSize);              //内存清零		
		memcpy(pTemp1, pNTHeader_Base, dwMoveSize); //从NT头基址开始复制到缓冲区
		//5.4 清空原先的NT头以及节表数组
		memset(pNTHeader_Base, 0, dwMoveSize);
		//5.5 将缓冲区的数据复制到DOS存根的基址处
		memcpy(pDosSub_Base, pTemp1, dwMoveSize);
		//5.6 释放申请的缓冲区
		free(pTemp1);
		//5.7 修正一堆东西
		//修正e_lfanew
		pDosHeader_Base->e_lfanew = sizeof(IMAGE_DOS_HEADER);
		//修正NT头基址
		pNTHeader_Base = (PIMAGE_NT_HEADERS)((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
		//修正文件头基址
		pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
		//修正可选头基址
		pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + IMAGE_SIZEOF_FILE_HEADER);
		//修正节表数组基址
		pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);
	}

	//-------------------------------步骤3：初始化新增节表头-----------------------------------------------
	//1.填充Name
	CHAR szName[] = ".new";
	memcpy(pSectionHeaderGroup_Base[numberOfSection].Name, szName, 8);
	//2.填充VirtualSize
	pSectionHeaderGroup_Base[numberOfSection].Misc.VirtualSize = NewSectionSize;
	//3.填充VirtualAddress(RVA,需要内存对齐）
	pSectionHeaderGroup_Base[numberOfSection].VirtualAddress = Align(pSectionHeaderGroup_Base[numberOfSection - 1].Misc.VirtualSize + pSectionHeaderGroup_Base[numberOfSection - 1].VirtualAddress, pOptionHeader_Base->SectionAlignment);//内存中的偏移
	//4.填充SizeOfRawData（需要文件对齐）
	pSectionHeaderGroup_Base[numberOfSection].SizeOfRawData = Align(NewSectionSize, pOptionHeader_Base->FileAlignment);//文件中对齐后的大小
	//5.填充PointerToRawData(FOA,需要文件对齐）
	pSectionHeaderGroup_Base[numberOfSection].PointerToRawData = Align(pSectionHeaderGroup_Base[numberOfSection - 1].PointerToRawData + pSectionHeaderGroup_Base[numberOfSection - 1].SizeOfRawData, pOptionHeader_Base->FileAlignment);//文件中的偏移
	//6.填充几个不重要的（全部填0）
	pSectionHeaderGroup_Base[numberOfSection].PointerToRelocations = 0;
	pSectionHeaderGroup_Base[numberOfSection].PointerToLinenumbers = 0;
	pSectionHeaderGroup_Base[numberOfSection].NumberOfRelocations = 0;
	pSectionHeaderGroup_Base[numberOfSection].NumberOfLinenumbers = 0;
	//7.填充Characteristics
	pSectionHeaderGroup_Base[numberOfSection].Characteristics |= pSectionHeaderGroup_Base->Characteristics;//默认代码节
	pSectionHeaderGroup_Base[numberOfSection].Characteristics |= 0xC0000040;
	//8.新节表的末尾填充40字节的0
	memset(&pSectionHeaderGroup_Base[numberOfSection + 1], 0, IMAGE_SIZEOF_SECTION_HEADER);

	//-------------------------------步骤4：修正PE头各种属性-----------------------------------------------
	//1.修复节数量（+1）
	pFileHeader_Base->NumberOfSections++;
	numberOfSection = pFileHeader_Base->NumberOfSections;
	//2.修复内存镜像大小（0x1000可以替换成任何大小，因为已经用了对齐算法）
	pOptionHeader_Base->SizeOfImage += Align(NewSectionSize, pOptionHeader_Base->SectionAlignment);
	//sizeofheads不会变，因为新增的节表头是在sizeofheads的空白区域内

	//-------------------------------步骤5：获得新的文件大小-----------------------------------------------
	//获取旧的文件大小
	DWORD dwOldSize = pSectionHeaderGroup_Base[numberOfSection - 2].PointerToRawData + pSectionHeaderGroup_Base[numberOfSection - 2].SizeOfRawData;
	//新的文件大小
	DWORD dwNewSize = pSectionHeaderGroup_Base[numberOfSection - 1].SizeOfRawData + pSectionHeaderGroup_Base[numberOfSection - 1].PointerToRawData;
	//将新的文件大小传递出去
	*NewFileSize = dwNewSize;

	//-------------------------------步骤6：获得新的文件缓存指针-----------------------------------------------
	//1.申请新的文件缓存区并清零
	*pNewFileBuffer = (PCHAR)malloc(dwNewSize);
	if (!*pNewFileBuffer)
	{
		printf("申请新的缓冲区失败 \r\n");
		free(pFileBuffer);
		return FALSE;
	}
	memset(*pNewFileBuffer, 0, dwNewSize);
	//2.将旧的文件缓存区复制到新的文件缓存区
	memcpy(*pNewFileBuffer, pFileBuffer, dwOldSize);
	//3.释放旧的文件缓存区
	free(pFileBuffer);

	return TRUE;
}


//【封装函数】BufferToFile：将文件缓存写入到硬盘文件
//【参数1】FilePath：待写入的硬盘文件的路径名    //一级指针
//【参数2】FileSize：待写入的文件大小   
//【参数3】pFileBuffer:文件缓存指针   //一级指针
//【返回值】BOOL ：成功返回TRUE，失败返回FALSE
BOOL BufferToFile(IN PCHAR FilePath, IN DWORD FileSize, IN PCHAR pFileBuffer)
{
	//1.打开文件名
	FILE* pFile = fopen(FilePath, "wb");
	if (!pFile)
	{
		printf("打开文件失败！ \r\n");
		return FALSE;
	}

	//2.写入硬盘
	fwrite(pFileBuffer, FileSize, 1, pFile);

	//3.关闭文件名
	fclose(pFile);

	//4.释放文件缓存
	free(pFileBuffer);

	return TRUE;
}


//【封装函数】Encryption ：对某一段缓存进行取反操作的加密
//【参数1】pFileBuffer:文件缓存指针  //一级指针
//【参数2】FileSize：文件缓存的大小
VOID Encryption(IN PCHAR pFileBuffer, IN DWORD FileSize)
{	
	for (DWORD i = 0; i < FileSize; i++)
	{
		pFileBuffer[i] = ~pFileBuffer[i];
	}
}


//【封装函数】Decryption ：对某一段缓存进行取反操作的解密
//【参数1】pFileBuffer:文件缓存指针  //一级指针
//【参数2】FileSize：文件缓存的大小
//【返回值】BOOL ：成功返回TRUE，失败返回FALSE
BOOL Decryption(IN PCHAR pFileBuffer, IN DWORD FileSize)
{
	for (DWORD i = 0; i < FileSize; i++)
	{
		pFileBuffer[i] = ~pFileBuffer[i];
	}

	if (*(short*)pFileBuffer != 0x5A4D)
	{
		printf("解密出错！");
		return FALSE;
	}

	return TRUE;
}


//【封装函数】CopyLastSection：拷贝文件最后一个节的内容到新申请的缓存中
//【参数1】pFileBuffer:文件缓存指针   //一级指针
//【参数2】pNewBuffer:指向“新申请的存放最后一个节的缓存的指针”的指针  //二级指针
//【参数3】Newsize ：新申请的缓存的大小
//【返回值】BOOL ：成功返回TRUE，失败返回FALSE
BOOL CopyLastSection(IN PCHAR pFileBuffer, OUT PCHAR* pNewBuffer, OUT DWORD* Newsize)
{
//1.获取DOS头基址
PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
//2.获取NT头基址
PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
//3.获取文件头基址
PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
//4.获取可选头基址	
PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
//5.获取节表头数组基址
PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);
//6.获取最后一个节的基址
PCHAR LastSectionBase = PCHAR((PUCHAR)pFileBuffer + pSectionHeaderGroup_Base[pFileHeader_Base->NumberOfSections - 1].PointerToRawData);
//7.获取最后一个节的大小
 *Newsize = pSectionHeaderGroup_Base[pFileHeader_Base->NumberOfSections - 1].SizeOfRawData;
//8.申请缓存
*pNewBuffer = (PCHAR)malloc(*Newsize);
if (!*pNewBuffer)
{
	printf("分配空间失败!");
	free(pFileBuffer);
	return FALSE;
}
//9.内存清零
memset(*pNewBuffer, 0, *Newsize);
//10.拷贝最后一个节到新申请的缓存
memcpy(*pNewBuffer, LastSectionBase, *Newsize);
//11.释放文件缓存
free(pFileBuffer);

return TRUE;
}


//【封装函数】FileBufferToImageBuffer：拉伸文件缓存成为镜像缓存
//【参数1】pFileBuffer：文件缓存指针    //一级指针
//【参数2】pImageBuffer：指向“镜像缓存指针”的指针   //二级指针
//【返回值】BOOL ：成功返回TRUE，失败返回FALSE
BOOL FileBufferToImageBuffer(IN PCHAR pFileBuffer, OUT PCHAR* pImageBuffer)
{
	//--------------------------1.获取各种基址---------------------------------------------
	//1.获取DOS头基址(就是文件缓存的基址）
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader_Base->e_magic != 0x5A4D)
	{
		printf("没有MZ标志\n");
		return FALSE;
	}
	//2.获取NT头基址（从文件缓存的基址偏移e_lfanew的距离)
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	if (pNTHeader_Base->Signature != 0x4550)
	{
		printf("找不到PE标志\n");
		return FALSE;
	}
	//3.获取文件头基址
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.获取可选头基址（可选头紧挨着文件头末尾,所以可选头基址=文件头基址+文件头大小）	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.获取节表头数组基址（节表数组紧挨着可选头末尾,所以节表数组基址=可选头基址+可选头大小）
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);

	//--------------------------2.申请镜像缓存---------------------------------------------
	*pImageBuffer = (PCHAR)malloc(pOptionHeader_Base->SizeOfImage);
	if (!*pImageBuffer)
	{
		printf("内存分配失败");
		return FALSE;
	}
	memset(*pImageBuffer, 0, pOptionHeader_Base->SizeOfImage);

	//--------------------------3.复制PE头---------------------------------------------
	memcpy(*pImageBuffer, pFileBuffer, pOptionHeader_Base->SizeOfHeaders);

	//--------------------------4.复制节---------------------------------------------
	for (int i = 0; i < pFileHeader_Base->NumberOfSections; i++)
	{
		//1）得到节在内存中的位置
		DWORD RVA = pSectionHeaderGroup_Base[i].VirtualAddress;
		//2）取得节在文件中的位置
		DWORD FOA = pSectionHeaderGroup_Base[i].PointerToRawData;
		//3）得到节对齐后的大小
		DWORD size = pSectionHeaderGroup_Base[i].SizeOfRawData;
		//4）往ImageBuffer中复制节数据
		memcpy(PCHAR((PUCHAR)*pImageBuffer + RVA), PCHAR((PUCHAR)pFileBuffer + FOA), size);
	}

	return TRUE;
}


//【封装函数】RestoreRelocation1：对镜像缓存进行重定位表修复   //注意：还有一种是文件缓存的重定位表修复
//【参数1】pImageBuffer:镜像缓存指针  //一级指针
VOID RestoreRelocation1(IN PCHAR pImageBuffer)
{
	//-------------------------------1.定位PE结构各种基址---------------------------------------------	
	//1.获取DOS头基址
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pImageBuffer;
	//2.获取NT头基址
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pImageBuffer + pDosHeader_Base->e_lfanew);
	//3.获取文件头基址
	PIMAGE_FILE_HEADER pFileHeader_Base = PIMAGE_FILE_HEADER((PUCHAR)pNTHeader_Base + 4);
	//4.获取可选头基址	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = PIMAGE_OPTIONAL_HEADER((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));

	//-------------------------------2.获取重定位表的基址---------------------------------------------
	//1.获取重定位表基址的RVA
	DWORD pRelocationBase_RVA = pOptionHeader_Base->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (!pRelocationBase_RVA)
	{
		printf("该PE文件不存在重定位表,不需要修复 \r\n");
		return ;
	}
	//2.获取重定位表在镜像缓存中的基址
	PIMAGE_BASE_RELOCATION pRelocationBlock_Base = PIMAGE_BASE_RELOCATION(pImageBuffer + pRelocationBase_RVA);

	//-------------------------------3.获得新旧镜像基址的差值、修正镜像基址----------------------------------------------------
	//1.获得新旧镜像基址的差值(备用）
	DWORD ImageBase_Sub = (DWORD)pImageBuffer - pOptionHeader_Base->ImageBase;
	//2.修正镜像基址
	pOptionHeader_Base->ImageBase = (DWORD)pImageBuffer;

	//-------------------------------4.修复重定位表---------------------------------------------
	//1.循环遍历直到结构体VirtualAddress-SizeOfBlock都为NULL
	while (pRelocationBlock_Base->VirtualAddress && pRelocationBlock_Base->SizeOfBlock)
	{
		//1.获取当前重定位块的基址(RVA类型）
		DWORD pRelocationBlockBase_RVA = pRelocationBlock_Base->VirtualAddress;
		//2.获取当前重定位块的大小
		DWORD pRelocationBlock_Size = pRelocationBlock_Base->SizeOfBlock;
		//3.获取重定位数组的基址(重定位数组在重定位块基址往后偏移8个字节处）
		PWORD pRelData_Base = PWORD((PUCHAR)pRelocationBlock_Base + 8);
		//4.获取重定位数组内的元素个数
		DWORD dwRelNumber = (pRelocationBlock_Base->SizeOfBlock - 8) / 2;
		//5.循环修复重定位数组中的元素（每个元素都是16位宽度）
		for (size_t i = 0; i < dwRelNumber; i++)
		{
			//5.1 获取高4位的值
			WORD dwHigh_4 = (pRelData_Base[i] & 0xF000) >> 12;
			//5.2获取低12位的值
			WORD dwLow_12 = pRelData_Base[i] & 0xFFF;
			//5.3 获取需要修复的值（RVA类型）  //需要修复的值 =低12位的值+ VirtualAddress
			DWORD dwDataRVA = dwLow_12 + pRelocationBlockBase_RVA;
			//5.4获取需要修复的值的基址（在文件缓存中的位置）
			PDWORD pData = PDWORD((PUCHAR)pImageBuffer + dwDataRVA);
			//5.5修复需要重定位的元素
			if (dwHigh_4 == 3)
			{
				*pData = *pData + ImageBase_Sub;
			}
		}
		//6.将重定位块的基址指向下一个重定位块
		pRelocationBlock_Base = (PIMAGE_BASE_RELOCATION)((PUCHAR)pRelocationBlock_Base + pRelocationBlock_Base->SizeOfBlock);
	}
}


//【封装函数】RestoreRelocation2：对文件缓存进行重定位表修复 
//【参数1】pFileBuffer:文件缓存指针
//【参数2】NewImageBase：新的ImageBase(自己设定）
//【返回值】BOOL ：成功返回TRUE，失败返回FALSE
VOID RestoreRelocation2(IN PCHAR pFileBuffer, IN DWORD NewImageBase)
{
	//--------------------------1.获取文件缓存的各种基址---------------------------------------------
	PIMAGE_DOS_HEADER      pDosHeader_Base = NULL;             //DOS头基址
	PIMAGE_NT_HEADERS      pNTHeader_Base = NULL;              //NT头基址
	PIMAGE_FILE_HEADER     pFileHeader_Base = NULL;            //文件头基址
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = NULL;          //可选头基址

	//1.获取DOS头基址(就是文件缓存的基址）
	pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	//2.获取NT头基址（从文件缓存的基址偏移e_lfanew的距离)
	pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	//3.获取文件头基址
	pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.获取可选头基址（可选头紧挨着文件头末尾,所以可选头基址=文件头基址+文件头大小）	
	pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));

	//--------------------------2.获取重定位表的基址---------------------------------------------
	//1.获取重定位表基址的RVA
	DWORD pRelocationBase_RVA = pOptionHeader_Base->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	//2.判断该PE文件是否有重定位表
	if (!pRelocationBase_RVA)
	{
		printf("该PE文件不存在重定位表，不需要修复 \r\n");
		return ;
	}
	//3.获取重定位表在文件缓存中的基址
	PIMAGE_BASE_RELOCATION pRelocationBlock_Base = (PIMAGE_BASE_RELOCATION)((PUCHAR)pFileBuffer + RvaToFoa(pFileBuffer, pRelocationBase_RVA));


	//-------------------------------3.获得新旧镜像基址的差值、修正镜像基址----------------------------------------------------
	//1.获得新旧镜像基址的差值(备用）
	DWORD ImageBase_Sub = NewImageBase - pOptionHeader_Base->ImageBase;
	//2.修正镜像基址
	pOptionHeader_Base->ImageBase = NewImageBase;


	//--------------------------4.修复重定位表---------------------------------------------
	//1.循环遍历直到结构体VirtualAddress-SizeOfBlock都为NULL
	DWORD dwCount = 1;
	while (pRelocationBlock_Base->VirtualAddress && pRelocationBlock_Base->SizeOfBlock)
	{
		//1.获取当前重定位块的基址(RVA类型）
		DWORD pRelocationBlockBase_RVA = pRelocationBlock_Base->VirtualAddress;
		//2.获取当前重定位块的大小
		DWORD pRelocationBlock_Size = pRelocationBlock_Base->SizeOfBlock;
		//3.获取重定位数组的基址(重定位数组在重定位块基址往后偏移8个字节处）
		PWORD pRelData_Base = (PWORD)pRelocationBlock_Base + 8;
		//4.获取重定位数组内的元素个数
		DWORD dwRelNumber = (pRelocationBlock_Base->SizeOfBlock - 8) / 2;
		//5.循环修复重定位数组中的元素（每个元素都是16位宽度）
		for (size_t i = 0; i < dwRelNumber; i++)
		{
			//5.1 获取高4位的值
			WORD dwHigh_4 = (pRelData_Base[i] & 0xF000) >> 12;
			//5.2获取低12位的值
			WORD dwLow_12 = pRelData_Base[i] & 0xFFF;
			//5.3 获取需要修复的值（RVA类型）  //需要修复的值 =低12位的值+ VirtualAddress
			DWORD dwDataRVA = dwLow_12 + pRelocationBlockBase_RVA;
			//5.4 获取需要修复的值（FOA类型）
			DWORD dwDataFOA = RvaToFoa(pFileBuffer, dwDataRVA);
			//5.5获取需要修复的值的基址（在文件缓存中的位置）
			PDWORD pData = PDWORD((DWORD)pFileBuffer + dwDataFOA);       
			//5.6修复需要重定位的元素
			if (dwHigh_4 == 3)
			{
				*pData = *pData + ImageBase_Sub;
			}
		}
		//6.将重定位块的基址指向下一个重定位块
		pRelocationBlock_Base = (PIMAGE_BASE_RELOCATION)((PCHAR)pRelocationBlock_Base + pRelocationBlock_Base->SizeOfBlock);
	}

}


//【封装函数】EnableDebugPrivilege：提升进程访问令牌权限
//【返回值】BOOL：成功返回TRUE，失败返回FALSE  
BOOL EnableDebugPrivilege()
{
	HANDLE hToken = NULL;
	//令牌权限结构体
	TOKEN_PRIVILEGES tp;

	//1.打开进程令牌并获取进程令牌句柄
	BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (FALSE == bRet)
	{
		MessageBoxA(NULL,"打开进程令牌失败！", NULL, NULL);
		return FALSE;
	}
	//2.获取本地系统的 pszPrivilegesName 特权的LUID值存放到tp结构体
	bRet = LookupPrivilegeValue(NULL,SE_DEBUG_NAME, &tp.Privileges[0].Luid);
	if (FALSE == bRet)
	{
		MessageBoxA(NULL,"获取LUID值失败！", NULL, NULL);
		CloseHandle(hToken);
		hToken = INVALID_HANDLE_VALUE;
		return FALSE;
	}
	//3.对tp结构体成员进行赋值
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	//5.将修改后的tp结构体写入进程令牌中
	bRet = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

	//6.AdjustTokenPrivileges返回FALSE，说明修改失败
	if (FALSE == bRet)
	{
		MessageBoxA(NULL,"提升进程令牌访问权限失败！", NULL, NULL);
		CloseHandle(hToken);
		hToken = INVALID_HANDLE_VALUE;
		return FALSE;
	}
	//6.AdjustTokenPrivileges返回TRUE，并不代表特权设置成功，还需要使用GetLastError来判断错误码返回值
	else
	{
		//根据错误码判断是否是特权都设置成功
		DWORD dwRet = GetLastError();
		//6.1错误码返回值为ERROR_SUCCESS，则表示所有特权设置成功
		if (ERROR_SUCCESS == dwRet)
		{
			CloseHandle(hToken);
			hToken = INVALID_HANDLE_VALUE;
			return TRUE;
		}
		//6.2若为ERROR_NOT_ALL_ASSIGNED，则表示并不是所有特权都设置成功
		else if (ERROR_NOT_ALL_ASSIGNED == dwRet)
		{
			MessageBoxA(NULL,"提升权限失败！，请以管理员身份运行", NULL, NULL);
			CloseHandle(hToken);
			hToken = INVALID_HANDLE_VALUE;
			return FALSE;
		}
		else
		{
			MessageBoxA(NULL, "提升权限失败！", NULL, NULL);
			CloseHandle(hToken);
			hToken = INVALID_HANDLE_VALUE;
			return FALSE;
		}
	}
}


//【封装函数】GetPidByName：通过进程名获取进程PID
//【参数1】szProcessName：进程名
//【返回值】DWORD ：进程PID
DWORD GetPidByName(IN const char* szProcessName)
{
	//1.初始化进程结构体
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	//2.获取进程快照句柄
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot失败\n");
		return -1;
	}
	//3.遍历进程快照
	BOOL bRet = Process32First(hSnap, &pe32);
	while (bRet)
	{
		//如果通过进程名对比发现相同进程名
		if (strcmp(pe32.szExeFile, szProcessName) == 0)
		{
			printf("Process Name: %s 的PID为: %d\n", pe32.szExeFile, pe32.th32ProcessID);
			//关闭进程快照句柄
			CloseHandle(hSnap);
			//返回进程PID并退出
			return pe32.th32ProcessID;
		}
		//如果通过进程名对比没有发现相同进程名，跳到下一个进程
		bRet = Process32Next(hSnap, &pe32);
	}
	//4.如果全部进程都没有找到符合的，关闭进程快照句柄
	CloseHandle(hSnap);
	//5.返回0表示没有找到符合的进程
	return 0;
}

//【封装函数】Is32PEFile:验证是否是合法的32位PE文件
//【参数1】pFileBuffer:文件缓存基址   //一级指针
//【返回值】BOOL：如果是32位PE文件，返回TRUE；如果不是，返回FALSE
BOOL Is32PEFile(LPVOID pFileBuffer)
{
	//-------------------------------1.定位PE结构各种基址---------------------------------------------	
	//1.获取DOS头基址
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	//2.获取NT头基址
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	//3.获取文件头基址
	PIMAGE_FILE_HEADER pFileHeader_Base = PIMAGE_FILE_HEADER((PUCHAR)pNTHeader_Base + 4);
	//4.获取可选头基址	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = PIMAGE_OPTIONAL_HEADER((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.获取节表头数组基址
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);

	//----------------------------------2.开始判断
	if (pDosHeader_Base->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return FALSE;
	}
	if (pNTHeader_Base->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标记\n");
		return FALSE;
	}

	if (pOptionHeader_Base->Magic== 0x10b)  //0x10b  32   0x20b 64
	{
		printf("是32位的PE文件\n");
		return TRUE;
	}
	else if (pOptionHeader_Base->Magic == 0x20b)
	{
		printf("是64位的PE文件\n");
		return FALSE;
	}
	else
	{
		printf("未知位数的PE文件\n");
		return FALSE;
	}
}

//【封装函数】GetAllThreadIdByProcessId： 根据 PID 获取获取该进程全部线程的 TID
//【参数1】ProcessId ： 进程 PID
//【参数2】pThreadId ： 数组用于保存线程TID
//【参数3】ThreadIdLen ：用于返回数组实际长度
//【返回值】BOOL：成功返回TRUE，失败返回FALSE
BOOL GetAllThreadIdByProcessId(IN ULONG ProcessId, IN ULONG* pThreadId, OUT ULONG* ThreadIdLen)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	ULONG Number = 0;

	// 把所有线程拍一个快照
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// 在使用 Thread32First 前初始化 THREADENTRY32 的结构大小.
	te32.dwSize = sizeof(THREADENTRY32);

	// 现在获取系统线程列表, 并显示与指定进程相关的每个线程的信息
	do {
		// 比对是否为该进程线程
		if (te32.th32OwnerProcessID == ProcessId)
		{
			// 是的话保存到线程数组中
			pThreadId[Number] = te32.th32ThreadID;
			Number++;
		}
	} while (Thread32Next(hThreadSnap, &te32));

	if (!Number)
		return FALSE;
	// 修改线程数量
	*ThreadIdLen = Number;
	return TRUE;
}


//【封装函数】RestoreIAT：修复IAT表
//【参数1】pImageBuffer:镜像缓存指针  //一级指针
//【返回值】BOOL：成功返回TRUE，失败返回FALSE
BOOL RestoreIAT(IN PCHAR pImageBuffer)
{
	//-----------------------------------1.定位PE结构各种基址---------------------------------------------
	//1.获取DOS头基址(就是文件缓存的基址）
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pImageBuffer;
	//2.获取NT头基址
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pImageBuffer + pDosHeader_Base->e_lfanew);
	//3.获取文件头基址
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.获取可选头基址	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.获取导入表基址偏移（RVA类型）
	DWORD pImport_Base_RVA = pOptionHeader_Base->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	//判断该PE文件是否有导入表
	if (!pImport_Base_RVA)
	{
		printf("该PE文件不存在导入表 \r\n");
		return FALSE;
	}
	//6.获取导入表在镜像缓存中的基址
	PIMAGE_IMPORT_DESCRIPTOR pImport_Base = PIMAGE_IMPORT_DESCRIPTOR((PUCHAR)pImageBuffer + pImport_Base_RVA);

	//-----------------------------------------2.修复IAT表---------------------------------------------------
	//循环遍历
	while (pImport_Base->Name)
	{
		//1.获取导入表的模块名
		PUCHAR pDllName = PUCHAR((DWORD)pImageBuffer + pImport_Base->Name);
		//2.获取导入表的对应模块的基址
		HMODULE hModule = LoadLibraryA((LPCSTR)pDllName);
		if (!hModule)
		{
			return FALSE;
		}
		//3.获取导入表的INT表基址
		PDWORD pINT = (PDWORD)((PUCHAR)pImageBuffer + pImport_Base->OriginalFirstThunk);
		//4.获取导入表的IAT表基址
		PDWORD pIAT = (PDWORD)((PUCHAR)pImageBuffer + pImport_Base->FirstThunk);

		//5.循环获取函数地址并修正到IAT表内
		do
		{
			//1.定义函数地址变量
			DWORD  dwFunAddr = 0;
			//2.获得最高位的值
			DWORD  HIGH_1 = (*pINT) >> 31;
			//3.获得低31位的值
			DWORD LOW_31 = (*pINT) & 0x7FFFFFFF;

			//4.如果最高位为1，那么INT表内低31位存放的是函数序号
			if (HIGH_1)
			{
				//1.获得函数序号对应的函数地址
				dwFunAddr = (DWORD)GetProcAddress(hModule, (LPCSTR)LOW_31);
			}
			//4.如果最高位为0，INT表内存放的是IMPORT_BY_NAME结构体的RVA值
			else
			{
				//1.获取IMPORT_BY_NAME结构体在镜像缓存中的基址
				PIMAGE_IMPORT_BY_NAME pTemp = PIMAGE_IMPORT_BY_NAME((PUCHAR)pImageBuffer + *pINT);
				//2.获得IMPORT_BY_NAME结构体的Name成员
				LPCSTR pname = pTemp->Name;
				//3.获得Name对应的函数地址
				dwFunAddr = (DWORD)GetProcAddress(hModule, pname);
			}
			//5.如果获得的函数地址为空，则说明已经获取到尾部结束标记
			if (!dwFunAddr)
			{
				return FALSE;
			}
			//6.修正IAT表里的函数地址
			*pIAT = dwFunAddr;
			//7.递增指向下一个INT和IAT
			pINT++;
			pIAT++;

		} while (*pINT);

		//6.指向下一个导入表结构
		pImport_Base++;
	}

	return TRUE;
}


//【封装函数】MemGetFunctionAddrByName：通过函数名查找导出函数地址（针对的是断链抹除PE指纹的DLL）
//【参数1】pImageBuffer:镜像缓存指针  //一级指针
//【参数2】szName：函数名
//【参数3】g_Exp :导出表基址（断链抹除PE指纹之前保存过的一个全局变量）
//【返回值】函数的地址
PVOID MemGetFunctionAddrByName(IN PCHAR pImageBuffer, IN PCHAR szName,IN PCHAR g_Exp)
{
	//因为这个DLL是我们自己加载的，不是系统加载的，所以不能去exe的导入表里找函数地址
	//我们可以去加载的这个DLL的导出表里找函数地址
	//这就要求写DLL时一定要处理好导出函数名的问题

	//1.定位DLL的地址表基址,名称表基址,序号表基址
	PIMAGE_EXPORT_DIRECTORY ExportBase = (PIMAGE_EXPORT_DIRECTORY)g_Exp;
	LPDWORD pAddFunc = (LPDWORD)((DWORD)pImageBuffer + ExportBase->AddressOfFunctions);
	LPDWORD pAddName = (LPDWORD)((DWORD)pImageBuffer + ExportBase->AddressOfNames);
	LPWORD pAddOrdi = (LPWORD)((DWORD)pImageBuffer + ExportBase->AddressOfNameOrdinals);

	//2.遍历DLL的导出表获取函数的真正地址
	for (size_t i = 0; i < ExportBase->NumberOfNames; i++)
	{
		//1.获得名称表里的某一项：（函数名的RVA）
		DWORD pname_RVA = pAddName[i];
		//2.获得名称表里的某一项在镜像缓存中的基址（基址里面存放的是函数名字符串）
		PCHAR pname_Base = PCHAR((PUCHAR)pImageBuffer + pname_RVA);
		//3.对比传进来的函数名与名称表里的函数名
		if (strcmp(szName, pname_Base) == 0)
		{
			//注意：3张表的顺序是名称表-->序号表--->地址表
			//注意：名称表内的值是RVA，序号表内的值是序号，地址表内的值是RVA
			//注意：名称表内的函数名称一旦对比相同，就要把当前下标作为序号表的下标，找序号表相同下标的项的值
			//注意：序号表的项的值作为下标去地址表内查找，那一项的内容就是函数地址（RVA）

			//1.拿着当前下标去序号表里找相同下标的项
			DWORD pnumber = pAddOrdi[i];
			//2.把序号表里拿到的这一项的内容作为下标去地址表里查
			DWORD pAdd = pAddFunc[pnumber];
			//3.地址表里查到的值+ImageBase为真正函数地址
			PVOID funcadd = PVOID((PUCHAR)pImageBuffer + pAdd);
			//4.将真正函数地址作为返回值传递出去
			return funcadd;
		}
	}
	return NULL;
}

//【封装函数】MemGetFunctionAddrByOrdinals：通过导出函数序号查找函数地址（针对的是断链抹除PE指纹的DLL）
//【参数1】pImageBuffer:镜像缓存指针  //一级指针
//【参数2】dwOrdinal：函数序号
//【参数3】g_Exp :导出表基址（断链抹除PE指纹之前保存过的一个全局变量）
//【返回值】函数的地址
PVOID MemGetFunctionAddrByOrdinals(PCHAR pImageBuffer, DWORD dwOrdinal, IN PCHAR g_Exp)
{
	//1.定位地址表,名称表,序号表
	PIMAGE_EXPORT_DIRECTORY ExportBase = (PIMAGE_EXPORT_DIRECTORY)g_Exp;
	LPDWORD pAddFunc = (LPDWORD)(pImageBuffer + ExportBase->AddressOfFunctions);
	//2.判断序号是否有效
	if (dwOrdinal - ExportBase->Base > ExportBase->NumberOfFunctions)
	{
		return NULL;
	}
	//3.用序号减去序号的base，差值作为下标去地址表内查找
	DWORD pAdd = pAddFunc[dwOrdinal - ExportBase->Base];
	//4.地址表里查到的值+ImageBase为真正函数地址
	PVOID funcadd = PVOID((PUCHAR)pImageBuffer + pAdd);
	//5.将真正函数地址作为返回值传递出去
	return funcadd;
}


//【封装函数】ClaenPeInfo:抹除PE指纹
//【参数1】pImageBuffer:镜像缓存指针  //一级指针
//【参数2】g_Exp:指向“导出表基址”的指针  //二级指针
VOID ClaenPeInfo(IN PCHAR pImageBuffer,OUT PCHAR* g_Exp)
{
	//--------------------------1.定位PE结构各种基址---------------------------------------------
	//1.获取DOS头基址
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pImageBuffer;
	//2.获取NT头基址
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pImageBuffer + pDosHeader_Base->e_lfanew);
	//3.获取文件头基址
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.获取可选头基址	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));

	//-------------------------2.备份导出表的基址（后面调用导出表内的函数要用到）--------------------------------
	*g_Exp = PCHAR((PUCHAR)pImageBuffer + pOptionHeader_Base->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//--------------------------------------3.抹除PE头--------------------------------------------------------
	memset(pImageBuffer, 0, pOptionHeader_Base->SectionAlignment);
}

//-----------------------------------------------------------------------------------------------------------------
//1.定义结构体UNICODE_STRING
typedef struct _UNICODE_STRING
{
	USHORT Length;                                                          //0x0
	USHORT MaximumLength;                                                   //0x2
	WCHAR* Buffer;                                                          //0x4
}UNICODE_STRING, *PUNICODE_STRING;
//2.定义结构体PEB_LDR_DATA
typedef struct _PEB_LDR_DATA
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	struct _LIST_ENTRY InLoadOrderModuleList;                               //0xc
	struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x14
	struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x1c
	VOID* EntryInProgress;                                                  //0x24
	UCHAR ShutdownInProgress;                                               //0x28
	VOID* ShutdownThreadId;                                                 //0x2c
}PEB_LDR_DATA, *PPEB_LDR_DATA;
//3.定义结构体LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x8
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x10
	VOID* DllBase;                                                          //0x18
	VOID* EntryPoint;                                                       //0x1c
	ULONG SizeOfImage;                                                      //0x20
	struct _UNICODE_STRING FullDllName;                                     //0x24
	struct _UNICODE_STRING BaseDllName;                                     //0x2c
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

//【封装函数】HideModule：隐藏模块
//【参数1】szModuleName：模块名
VOID HideModule(PCHAR szModuleName)
{
	//注意：TEB-->PEB-->PEB_LDR_DATA-->PLDR_DATA_TABLE_ENTRY-->PLIST_ENTRY
	//--------------------------------1.获取各种基址---------------------------------------------
	//1.获得传进来的模块名的模块基址
	HMODULE hMod = GetModuleHandleA(szModuleName);
	//2.获取PEB_LDR_DATA的基址
	PPEB_LDR_DATA pLdr_Base = NULL;
	__asm
	{
		MOV EAX, FS: [0x30]
		MOV EAX, [EAX + 0xC]
		MOV pLdr_Base, EAX
	}
	//3.获取PEB_LDR_DATA中的成员InLoadOrderModuleList的地址
	//注意：InLoadOrderModuleList是大结构体PEB_LDR_DATA中的嵌套结构体
	//先用pLdr_Base->InLoadOrderModuleList取得InLoadOrderModuleList结构体，然后用&(pLdr_Base->InLoadOrderModuleList)取得InLoadOrderModuleList的基址
	PLIST_ENTRY pInLoadOrderModuleList_Base = &(pLdr_Base->InLoadOrderModuleList);
	//4.把结构体InLoadOrderModuleList中的成员Flink指向的指针作为第一个双向链表的基址
	PLIST_ENTRY FirstList_Base = pInLoadOrderModuleList_Base->Flink;
	//5.把第一个双向链表的基址作为当前双向链表的基址
	PLIST_ENTRY pCurrentList_Base = FirstList_Base;
	//6.从当前双向链表开始遍历查询模块，查到符合的就断链
	do
	{
		//因为大结构体PLDR_DATA_TABLE_ENTRY内嵌套小结构体PLIST_ENTRY，还刚好嵌套在头部，所以两者的基址是相同的
		//1.将PLIST_ENTRY的基址赋给PLDR_DATA_TABLE_ENTRY
		PLDR_DATA_TABLE_ENTRY pCurrentLDREntry_Base = (PLDR_DATA_TABLE_ENTRY)pCurrentList_Base;
		//2.如果传递进来的模块的地址与当前模块的地址相同，那么进行断链操作
		if (hMod == pCurrentLDREntry_Base->DllBase)
		{
			//更改第1个链
			pCurrentLDREntry_Base->InLoadOrderLinks.Blink->Flink = pCurrentLDREntry_Base->InLoadOrderLinks.Flink;
			pCurrentLDREntry_Base->InLoadOrderLinks.Flink->Blink = pCurrentLDREntry_Base->InLoadOrderLinks.Blink;

			//更改第2个链
			pCurrentLDREntry_Base->InMemoryOrderLinks.Blink->Flink = pCurrentLDREntry_Base->InMemoryOrderLinks.Flink;
			pCurrentLDREntry_Base->InMemoryOrderLinks.Flink->Blink = pCurrentLDREntry_Base->InMemoryOrderLinks.Blink;

			//更改第3个链
			pCurrentLDREntry_Base->InInitializationOrderLinks.Blink->Flink = pCurrentLDREntry_Base->InInitializationOrderLinks.Flink;
			pCurrentLDREntry_Base->InInitializationOrderLinks.Flink->Blink = pCurrentLDREntry_Base->InInitializationOrderLinks.Blink;

			//修改内存属性
			DWORD dwOldProct = 0;
			VirtualProtect(pCurrentLDREntry_Base->DllBase, 0x1000, PAGE_READWRITE, &dwOldProct);
			//抹除PE指纹
			memset(pCurrentLDREntry_Base->DllBase, 0, 0x1000);
			//恢复内存属性
			VirtualProtect(pCurrentLDREntry_Base->DllBase, 0x1000, dwOldProct, NULL);

			break;
		}
		//3.指针从当前的双向链表移到下一位		
		pCurrentList_Base = pCurrentList_Base->Flink;

	} while (FirstList_Base != pCurrentList_Base);
}
//------------------------------------------------------------------------------------------------------------------------