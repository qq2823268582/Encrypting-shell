# define _CRT_SECURE_NO_WARNINGS
#include   "iostream"
# include  "windows.h"
#include   "Pefunc.h"


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


//【封装函数】RestoreRelocation：对镜像缓存进行重定位表修复   //注意：还有一种是文件缓存的重定位表修复
//【参数1】pImageBuffer:镜像缓存指针  //一级指针
//【返回值】BOOL ：成功返回TRUE，失败返回FALSE
BOOL RestoreRelocation(IN PCHAR pImageBuffer)
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
		printf("该PE文件不存在重定位表 \r\n");
		return FALSE;
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
	return TRUE;
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
		MessageBoxA(NULL, "打开进程令牌失败！", NULL, NULL);
		return FALSE;
	}
	//2.获取本地系统的 pszPrivilegesName 特权的LUID值存放到tp结构体
	bRet = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
	if (FALSE == bRet)
	{
		MessageBoxA(NULL, "获取LUID值失败！", NULL, NULL);
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
		MessageBoxA(NULL, "提升进程令牌访问权限失败！", NULL, NULL);
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
			MessageBoxA(NULL, "提升权限失败！，请以管理员身份运行", NULL, NULL);
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