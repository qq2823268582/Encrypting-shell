# define _CRT_SECURE_NO_WARNINGS
#include   "iostream"
# include  "windows.h"
#include   <TlHelp32.h>
#include   "Pe.h"


//����װ������Align:������㺯��
//������1��size������ǰ�Ĵ�С
//������2��ALIGN_BASE�����������
//������ֵ��DWORD�������Ĵ�С
DWORD Align(IN DWORD size, IN DWORD ALIGN_BASE)
{
	if (size % ALIGN_BASE != 0)
	{
		size = (size / ALIGN_BASE + 1) * ALIGN_BASE;
	}
	return size;
}


//����װ������FileToBuffer����ȡӲ���ļ����ļ�����
//������1��FilePath����ȡ��Ӳ���ļ���·����  //һ��ָ��
//������2��FileSize��ָ�򡰶�ȡ���ļ���С����ָ��  //һ��ָ��
//������3��pFileBuffer:ָ���ļ�����ָ�롱��ָ��  //����ָ��
//������ֵ��BOOL ���ɹ�����TRUE��ʧ�ܷ���FALSE
BOOL FileToBuffer(IN PCHAR FilePath, OUT DWORD* FileSize, OUT PCHAR* pFileBuffer)
{
	//1.���ļ���
	FILE* pFile = fopen(FilePath, "rb");
	if (!pFile)
	{
		printf("���ļ�ʧ�ܣ� \r\n");
		return FALSE;
	}

	//2.��ȡ�ļ���С
	fseek(pFile, 0, SEEK_END);
	DWORD Size = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	//3.�����ڴ�ռ�
	*pFileBuffer = (PCHAR)malloc(Size);
	if (!*pFileBuffer)
	{
		printf("����ռ�ʧ��!");
		fclose(pFile);
		return FALSE;
	}

	//4.��ȡ�ļ����ļ�������
	if (!fread(*pFileBuffer, Size, 1, pFile))
	{
		printf("��ȡ����ʧ��!");
		free(*pFileBuffer);
		fclose(pFile);
		return FALSE;
	}

	//5.�ر��ļ���
	fclose(pFile);

	*FileSize = Size;

	return TRUE;
}


//����װ������RvaToFoa:��Rvaת��ΪFoa
//������1��pFileBuffer:�ļ�����ָ�� //һ��ָ��
//������2��RVA:����ڴ�ƫ�� 
//������ֵ��DWORD������ļ�ƫ��FOA
DWORD RvaToFoa(IN PCHAR pFileBuffer, IN DWORD RVA)
{
	//-------------------------------1.��λPE�ṹ���ֻ�ַ------------------------------------	
	//1.��ȡDOSͷ��ַ
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	//2.��ȡNTͷ��ַ
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	//3.��ȡ�ļ�ͷ��ַ
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.��ȡ��ѡͷ��ַ	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.��ȡ�ڱ�ͷ�����ַ
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);

	//--------------------------2.��RVA���ļ�ͷ��ʱ----------------------------------
	if (RVA < pOptionHeader_Base->SizeOfHeaders)
	{
		return RVA;
	}

	//--------------------------3.��RVA�ڽ�����ʱ---------------------------------------------
	for (int i = 0; i < pFileHeader_Base->NumberOfSections; i++)
	{
		//1.��ȡ��ͷƫ�ƣ�RVA���ͣ�
		DWORD SectionHead_Offset = pSectionHeaderGroup_Base[i].VirtualAddress;
		//2.��ȡ����ʵ��С
		DWORD Section_Size = pSectionHeaderGroup_Base[i].Misc.VirtualSize;
		//3.��ȡ��βƫ�ƣ�RVA���ͣ�
		DWORD SectionTail_Offset = SectionHead_Offset + Section_Size;
		//4.�ж�RVA�Ƿ��ڽ����ڣ�SectionHead_Offset <= RVA< SectionTail_Offset��
		if (SectionHead_Offset <= RVA && RVA < SectionTail_Offset)
		{
			DWORD FOA = pSectionHeaderGroup_Base[i].PointerToRawData + (RVA - SectionHead_Offset);
			return FOA;
		}
	}
	//--------------------------4.���������RVA������Ч��Χ----------------------------------
	printf("RVA������Ч��Χ��ת��ʧ�ܣ�\n");
	return 0;
}


//����װ������FoaToRva:��Foaת��ΪRva
//������1��pFileBuffer:�ļ�����ָ�� //һ��ָ��
//������2��FOA:�ļ����ƫ�� 
//������ֵ��DWORD���ڴ����ƫ��RVA  
DWORD FoaToRva(IN PCHAR pFileBuffer, IN DWORD FOA)
{
	//-------------------------------1.��λPE�ṹ���ֻ�ַ------------------------------------	
	//1.��ȡDOSͷ��ַ
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	//2.��ȡNTͷ��ַ
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	//3.��ȡ�ļ�ͷ��ַ
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.��ȡ��ѡͷ��ַ	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.��ȡ�ڱ�ͷ�����ַ
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);

	//--------------------------2.��FOA���ļ�ͷ��ʱ----------------------------------
	if (FOA < pOptionHeader_Base->SizeOfHeaders)
	{
		return FOA;
	}

	//--------------------------3.��FOA�ڽ�����ʱ---------------------------------------------
	for (int i = 0; i < pFileHeader_Base->NumberOfSections; i++)
	{
		//1.��ȡ��ͷƫ�ƣ�FOA���ͣ�
		DWORD SectionHead_Offset = pSectionHeaderGroup_Base[i].PointerToRawData;
		//2.��ȡ����ʵ��С
		DWORD Section_Size = pSectionHeaderGroup_Base[i].Misc.VirtualSize;
		//3.��ȡ��βƫ�ƣ�FOA���ͣ�
		DWORD SectionTail_Offset = SectionHead_Offset + Section_Size;
		//4.�ж�RVA�Ƿ��ڽ����ڣ�SectionHead_Offset <= RVA< SectionTail_Offset��
		if (SectionHead_Offset <= FOA && FOA < SectionTail_Offset)
		{
			DWORD RVA = pSectionHeaderGroup_Base[i].VirtualAddress + (FOA - SectionHead_Offset);
			return RVA;
		}
	}
	//--------------------------4.���������FOA������Ч��Χ----------------------------------
	printf("FOA������Ч��Χ,ת��ʧ�ܣ�\n");
	return -3;
}


//����װ������AddOneSectionHead�������ڱ�ͷ���޸�����PEͷ������
//������1��pFileBuffer:�ļ�����ָ�� //һ��ָ��
//������2��NewSectionSize �������ڵĴ�С���Զ����С��
//������3��pNewFileSize��ָ���µ��ļ���С����ָ�� //һ��ָ��
//������4��pNewFileBuffer ��ָ���µ��ļ�����ָ�롱��ָ��  //����ָ��
//������ֵ��BOOL ���ɹ�����TRUE��ʧ�ܷ���FALSE
BOOL AddOneSectionHead(IN PCHAR pFileBuffer, IN DWORD NewSectionSize, OUT DWORD* NewFileSize, OUT PCHAR* pNewFileBuffer)
{
	//-------------------------------1.��λPE�ṹ���ֻ�ַ------------------------------------	
	//1.��ȡDOSͷ��ַ
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	//2.��ȡNTͷ��ַ
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	//3.��ȡ�ļ�ͷ��ַ
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.��ȡ��ѡͷ��ַ	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.��ȡ�ڱ�ͷ�����ַ
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);

	//-------------------------------����2������ڱ�ͷ����ĩβ������֮��Ŀհ״�С-------------------------------------
	//1.��ýڵ�����
	DWORD numberOfSection = pFileHeader_Base->NumberOfSections;
	//2.��ȡ�ڱ�ͷ����ĩβ�Ļ�ַ
	PVOID pSectionHeaderGroup_Tail = &pSectionHeaderGroup_Base[numberOfSection];
	//3.��ȡ�ڱ�ͷ����ĩβ��ƫ��
	DWORD pSectionHeaderGroup_Tail_Offset = (DWORD)pSectionHeaderGroup_Tail - (DWORD)pFileBuffer;
	//4.��ȡ�ڱ�����ĩβ������֮��Ŀհ״�С(�հ״�С = ����ͷ�Ĵ�С -�ڱ�����ĩβ��ƫ�ƣ� 
	DWORD WhiteSize = pOptionHeader_Base->SizeOfHeaders - pSectionHeaderGroup_Tail_Offset;
	//5.����հ״�С����80����ôĨ��DOS������ݲ���NTͷ,�ڱ��������������ƶ���������e_lfanew
	if (WhiteSize < 80)
	{
		//5.1 Ĩ��DOS������ݣ�Ĩ���Ĵ�С = PE��־��ƫ�� -DOSͷ��Сƫ�ƣ�
		PVOID pDosSub_Base = PVOID((DWORD)pFileBuffer + sizeof(IMAGE_DOS_HEADER));
		memset(pDosSub_Base, 0, pDosHeader_Base->e_lfanew - sizeof(IMAGE_DOS_HEADER));
		//5.2 ����NTͷ���Ͻڱ�����Ĵ�С֮�ͣ�NTͷ��Сֱ����sizeof�ṹ�����󣬽ڱ�����Ĵ�С�õ����ڱ��С���Խڱ�������
		DWORD dwMoveSize = sizeof(IMAGE_NT_HEADERS) + pFileHeader_Base->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;
		//5.3 ���뻺�����ڴ棬��Ҫ�ƶ���NTͷ���Ͻڱ����鸴�Ƶ�������
		PVOID pTemp1 = (PUCHAR)malloc(dwMoveSize);       //���뻺�����ڴ�
		if (!pTemp1)
		{
			printf("���뻺����ʧ��!");
			free(pFileBuffer);
			return FALSE;
		}
		memset(pTemp1, 0, dwMoveSize);              //�ڴ�����		
		memcpy(pTemp1, pNTHeader_Base, dwMoveSize); //��NTͷ��ַ��ʼ���Ƶ�������
		//5.4 ���ԭ�ȵ�NTͷ�Լ��ڱ�����
		memset(pNTHeader_Base, 0, dwMoveSize);
		//5.5 �������������ݸ��Ƶ�DOS����Ļ�ַ��
		memcpy(pDosSub_Base, pTemp1, dwMoveSize);
		//5.6 �ͷ�����Ļ�����
		free(pTemp1);
		//5.7 ����һ�Ѷ���
		//����e_lfanew
		pDosHeader_Base->e_lfanew = sizeof(IMAGE_DOS_HEADER);
		//����NTͷ��ַ
		pNTHeader_Base = (PIMAGE_NT_HEADERS)((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
		//�����ļ�ͷ��ַ
		pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
		//������ѡͷ��ַ
		pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + IMAGE_SIZEOF_FILE_HEADER);
		//�����ڱ������ַ
		pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);
	}

	//-------------------------------����3����ʼ�������ڱ�ͷ-----------------------------------------------
	//1.���Name
	CHAR szName[] = ".new";
	memcpy(pSectionHeaderGroup_Base[numberOfSection].Name, szName, 8);
	//2.���VirtualSize
	pSectionHeaderGroup_Base[numberOfSection].Misc.VirtualSize = NewSectionSize;
	//3.���VirtualAddress(RVA,��Ҫ�ڴ���룩
	pSectionHeaderGroup_Base[numberOfSection].VirtualAddress = Align(pSectionHeaderGroup_Base[numberOfSection - 1].Misc.VirtualSize + pSectionHeaderGroup_Base[numberOfSection - 1].VirtualAddress, pOptionHeader_Base->SectionAlignment);//�ڴ��е�ƫ��
	//4.���SizeOfRawData����Ҫ�ļ����룩
	pSectionHeaderGroup_Base[numberOfSection].SizeOfRawData = Align(NewSectionSize, pOptionHeader_Base->FileAlignment);//�ļ��ж����Ĵ�С
	//5.���PointerToRawData(FOA,��Ҫ�ļ����룩
	pSectionHeaderGroup_Base[numberOfSection].PointerToRawData = Align(pSectionHeaderGroup_Base[numberOfSection - 1].PointerToRawData + pSectionHeaderGroup_Base[numberOfSection - 1].SizeOfRawData, pOptionHeader_Base->FileAlignment);//�ļ��е�ƫ��
	//6.��伸������Ҫ�ģ�ȫ����0��
	pSectionHeaderGroup_Base[numberOfSection].PointerToRelocations = 0;
	pSectionHeaderGroup_Base[numberOfSection].PointerToLinenumbers = 0;
	pSectionHeaderGroup_Base[numberOfSection].NumberOfRelocations = 0;
	pSectionHeaderGroup_Base[numberOfSection].NumberOfLinenumbers = 0;
	//7.���Characteristics
	pSectionHeaderGroup_Base[numberOfSection].Characteristics |= pSectionHeaderGroup_Base->Characteristics;//Ĭ�ϴ����
	pSectionHeaderGroup_Base[numberOfSection].Characteristics |= 0xC0000040;
	//8.�½ڱ��ĩβ���40�ֽڵ�0
	memset(&pSectionHeaderGroup_Base[numberOfSection + 1], 0, IMAGE_SIZEOF_SECTION_HEADER);

	//-------------------------------����4������PEͷ��������-----------------------------------------------
	//1.�޸���������+1��
	pFileHeader_Base->NumberOfSections++;
	numberOfSection = pFileHeader_Base->NumberOfSections;
	//2.�޸��ڴ澵���С��0x1000�����滻���κδ�С����Ϊ�Ѿ����˶����㷨��
	pOptionHeader_Base->SizeOfImage += Align(NewSectionSize, pOptionHeader_Base->SectionAlignment);
	//sizeofheads����䣬��Ϊ�����Ľڱ�ͷ����sizeofheads�Ŀհ�������

	//-------------------------------����5������µ��ļ���С-----------------------------------------------
	//��ȡ�ɵ��ļ���С
	DWORD dwOldSize = pSectionHeaderGroup_Base[numberOfSection - 2].PointerToRawData + pSectionHeaderGroup_Base[numberOfSection - 2].SizeOfRawData;
	//�µ��ļ���С
	DWORD dwNewSize = pSectionHeaderGroup_Base[numberOfSection - 1].SizeOfRawData + pSectionHeaderGroup_Base[numberOfSection - 1].PointerToRawData;
	//���µ��ļ���С���ݳ�ȥ
	*NewFileSize = dwNewSize;

	//-------------------------------����6������µ��ļ�����ָ��-----------------------------------------------
	//1.�����µ��ļ�������������
	*pNewFileBuffer = (PCHAR)malloc(dwNewSize);
	if (!*pNewFileBuffer)
	{
		printf("�����µĻ�����ʧ�� \r\n");
		free(pFileBuffer);
		return FALSE;
	}
	memset(*pNewFileBuffer, 0, dwNewSize);
	//2.���ɵ��ļ����������Ƶ��µ��ļ�������
	memcpy(*pNewFileBuffer, pFileBuffer, dwOldSize);
	//3.�ͷžɵ��ļ�������
	free(pFileBuffer);

	return TRUE;
}


//����װ������BufferToFile�����ļ�����д�뵽Ӳ���ļ�
//������1��FilePath����д���Ӳ���ļ���·����    //һ��ָ��
//������2��FileSize����д����ļ���С   
//������3��pFileBuffer:�ļ�����ָ��   //һ��ָ��
//������ֵ��BOOL ���ɹ�����TRUE��ʧ�ܷ���FALSE
BOOL BufferToFile(IN PCHAR FilePath, IN DWORD FileSize, IN PCHAR pFileBuffer)
{
	//1.���ļ���
	FILE* pFile = fopen(FilePath, "wb");
	if (!pFile)
	{
		printf("���ļ�ʧ�ܣ� \r\n");
		return FALSE;
	}

	//2.д��Ӳ��
	fwrite(pFileBuffer, FileSize, 1, pFile);

	//3.�ر��ļ���
	fclose(pFile);

	//4.�ͷ��ļ�����
	free(pFileBuffer);

	return TRUE;
}


//����װ������Encryption ����ĳһ�λ������ȡ�������ļ���
//������1��pFileBuffer:�ļ�����ָ��  //һ��ָ��
//������2��FileSize���ļ�����Ĵ�С
VOID Encryption(IN PCHAR pFileBuffer, IN DWORD FileSize)
{	
	for (DWORD i = 0; i < FileSize; i++)
	{
		pFileBuffer[i] = ~pFileBuffer[i];
	}
}


//����װ������Decryption ����ĳһ�λ������ȡ�������Ľ���
//������1��pFileBuffer:�ļ�����ָ��  //һ��ָ��
//������2��FileSize���ļ�����Ĵ�С
//������ֵ��BOOL ���ɹ�����TRUE��ʧ�ܷ���FALSE
BOOL Decryption(IN PCHAR pFileBuffer, IN DWORD FileSize)
{
	for (DWORD i = 0; i < FileSize; i++)
	{
		pFileBuffer[i] = ~pFileBuffer[i];
	}

	if (*(short*)pFileBuffer != 0x5A4D)
	{
		printf("���ܳ���");
		return FALSE;
	}

	return TRUE;
}


//����װ������CopyLastSection�������ļ����һ���ڵ����ݵ�������Ļ�����
//������1��pFileBuffer:�ļ�����ָ��   //һ��ָ��
//������2��pNewBuffer:ָ��������Ĵ�����һ���ڵĻ����ָ�롱��ָ��  //����ָ��
//������3��Newsize ��������Ļ���Ĵ�С
//������ֵ��BOOL ���ɹ�����TRUE��ʧ�ܷ���FALSE
BOOL CopyLastSection(IN PCHAR pFileBuffer, OUT PCHAR* pNewBuffer, OUT DWORD* Newsize)
{
//1.��ȡDOSͷ��ַ
PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
//2.��ȡNTͷ��ַ
PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
//3.��ȡ�ļ�ͷ��ַ
PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
//4.��ȡ��ѡͷ��ַ	
PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
//5.��ȡ�ڱ�ͷ�����ַ
PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);
//6.��ȡ���һ���ڵĻ�ַ
PCHAR LastSectionBase = PCHAR((PUCHAR)pFileBuffer + pSectionHeaderGroup_Base[pFileHeader_Base->NumberOfSections - 1].PointerToRawData);
//7.��ȡ���һ���ڵĴ�С
 *Newsize = pSectionHeaderGroup_Base[pFileHeader_Base->NumberOfSections - 1].SizeOfRawData;
//8.���뻺��
*pNewBuffer = (PCHAR)malloc(*Newsize);
if (!*pNewBuffer)
{
	printf("����ռ�ʧ��!");
	free(pFileBuffer);
	return FALSE;
}
//9.�ڴ�����
memset(*pNewBuffer, 0, *Newsize);
//10.�������һ���ڵ�������Ļ���
memcpy(*pNewBuffer, LastSectionBase, *Newsize);
//11.�ͷ��ļ�����
free(pFileBuffer);

return TRUE;
}


//����װ������FileBufferToImageBuffer�������ļ������Ϊ���񻺴�
//������1��pFileBuffer���ļ�����ָ��    //һ��ָ��
//������2��pImageBuffer��ָ�򡰾��񻺴�ָ�롱��ָ��   //����ָ��
//������ֵ��BOOL ���ɹ�����TRUE��ʧ�ܷ���FALSE
BOOL FileBufferToImageBuffer(IN PCHAR pFileBuffer, OUT PCHAR* pImageBuffer)
{
	//--------------------------1.��ȡ���ֻ�ַ---------------------------------------------
	//1.��ȡDOSͷ��ַ(�����ļ�����Ļ�ַ��
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDosHeader_Base->e_magic != 0x5A4D)
	{
		printf("û��MZ��־\n");
		return FALSE;
	}
	//2.��ȡNTͷ��ַ�����ļ�����Ļ�ַƫ��e_lfanew�ľ���)
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	if (pNTHeader_Base->Signature != 0x4550)
	{
		printf("�Ҳ���PE��־\n");
		return FALSE;
	}
	//3.��ȡ�ļ�ͷ��ַ
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.��ȡ��ѡͷ��ַ����ѡͷ�������ļ�ͷĩβ,���Կ�ѡͷ��ַ=�ļ�ͷ��ַ+�ļ�ͷ��С��	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.��ȡ�ڱ�ͷ�����ַ���ڱ���������ſ�ѡͷĩβ,���Խڱ������ַ=��ѡͷ��ַ+��ѡͷ��С��
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);

	//--------------------------2.���뾵�񻺴�---------------------------------------------
	*pImageBuffer = (PCHAR)malloc(pOptionHeader_Base->SizeOfImage);
	if (!*pImageBuffer)
	{
		printf("�ڴ����ʧ��");
		return FALSE;
	}
	memset(*pImageBuffer, 0, pOptionHeader_Base->SizeOfImage);

	//--------------------------3.����PEͷ---------------------------------------------
	memcpy(*pImageBuffer, pFileBuffer, pOptionHeader_Base->SizeOfHeaders);

	//--------------------------4.���ƽ�---------------------------------------------
	for (int i = 0; i < pFileHeader_Base->NumberOfSections; i++)
	{
		//1���õ������ڴ��е�λ��
		DWORD RVA = pSectionHeaderGroup_Base[i].VirtualAddress;
		//2��ȡ�ý����ļ��е�λ��
		DWORD FOA = pSectionHeaderGroup_Base[i].PointerToRawData;
		//3���õ��ڶ����Ĵ�С
		DWORD size = pSectionHeaderGroup_Base[i].SizeOfRawData;
		//4����ImageBuffer�и��ƽ�����
		memcpy(PCHAR((PUCHAR)*pImageBuffer + RVA), PCHAR((PUCHAR)pFileBuffer + FOA), size);
	}

	return TRUE;
}


//����װ������RestoreRelocation1���Ծ��񻺴�����ض�λ���޸�   //ע�⣺����һ�����ļ�������ض�λ���޸�
//������1��pImageBuffer:���񻺴�ָ��  //һ��ָ��
VOID RestoreRelocation1(IN PCHAR pImageBuffer)
{
	//-------------------------------1.��λPE�ṹ���ֻ�ַ---------------------------------------------	
	//1.��ȡDOSͷ��ַ
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pImageBuffer;
	//2.��ȡNTͷ��ַ
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pImageBuffer + pDosHeader_Base->e_lfanew);
	//3.��ȡ�ļ�ͷ��ַ
	PIMAGE_FILE_HEADER pFileHeader_Base = PIMAGE_FILE_HEADER((PUCHAR)pNTHeader_Base + 4);
	//4.��ȡ��ѡͷ��ַ	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = PIMAGE_OPTIONAL_HEADER((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));

	//-------------------------------2.��ȡ�ض�λ��Ļ�ַ---------------------------------------------
	//1.��ȡ�ض�λ���ַ��RVA
	DWORD pRelocationBase_RVA = pOptionHeader_Base->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (!pRelocationBase_RVA)
	{
		printf("��PE�ļ��������ض�λ��,����Ҫ�޸� \r\n");
		return ;
	}
	//2.��ȡ�ض�λ���ھ��񻺴��еĻ�ַ
	PIMAGE_BASE_RELOCATION pRelocationBlock_Base = PIMAGE_BASE_RELOCATION(pImageBuffer + pRelocationBase_RVA);

	//-------------------------------3.����¾ɾ����ַ�Ĳ�ֵ�����������ַ----------------------------------------------------
	//1.����¾ɾ����ַ�Ĳ�ֵ(���ã�
	DWORD ImageBase_Sub = (DWORD)pImageBuffer - pOptionHeader_Base->ImageBase;
	//2.���������ַ
	pOptionHeader_Base->ImageBase = (DWORD)pImageBuffer;

	//-------------------------------4.�޸��ض�λ��---------------------------------------------
	//1.ѭ������ֱ���ṹ��VirtualAddress-SizeOfBlock��ΪNULL
	while (pRelocationBlock_Base->VirtualAddress && pRelocationBlock_Base->SizeOfBlock)
	{
		//1.��ȡ��ǰ�ض�λ��Ļ�ַ(RVA���ͣ�
		DWORD pRelocationBlockBase_RVA = pRelocationBlock_Base->VirtualAddress;
		//2.��ȡ��ǰ�ض�λ��Ĵ�С
		DWORD pRelocationBlock_Size = pRelocationBlock_Base->SizeOfBlock;
		//3.��ȡ�ض�λ����Ļ�ַ(�ض�λ�������ض�λ���ַ����ƫ��8���ֽڴ���
		PWORD pRelData_Base = PWORD((PUCHAR)pRelocationBlock_Base + 8);
		//4.��ȡ�ض�λ�����ڵ�Ԫ�ظ���
		DWORD dwRelNumber = (pRelocationBlock_Base->SizeOfBlock - 8) / 2;
		//5.ѭ���޸��ض�λ�����е�Ԫ�أ�ÿ��Ԫ�ض���16λ��ȣ�
		for (size_t i = 0; i < dwRelNumber; i++)
		{
			//5.1 ��ȡ��4λ��ֵ
			WORD dwHigh_4 = (pRelData_Base[i] & 0xF000) >> 12;
			//5.2��ȡ��12λ��ֵ
			WORD dwLow_12 = pRelData_Base[i] & 0xFFF;
			//5.3 ��ȡ��Ҫ�޸���ֵ��RVA���ͣ�  //��Ҫ�޸���ֵ =��12λ��ֵ+ VirtualAddress
			DWORD dwDataRVA = dwLow_12 + pRelocationBlockBase_RVA;
			//5.4��ȡ��Ҫ�޸���ֵ�Ļ�ַ�����ļ������е�λ�ã�
			PDWORD pData = PDWORD((PUCHAR)pImageBuffer + dwDataRVA);
			//5.5�޸���Ҫ�ض�λ��Ԫ��
			if (dwHigh_4 == 3)
			{
				*pData = *pData + ImageBase_Sub;
			}
		}
		//6.���ض�λ��Ļ�ַָ����һ���ض�λ��
		pRelocationBlock_Base = (PIMAGE_BASE_RELOCATION)((PUCHAR)pRelocationBlock_Base + pRelocationBlock_Base->SizeOfBlock);
	}
}


//����װ������RestoreRelocation2�����ļ���������ض�λ���޸� 
//������1��pFileBuffer:�ļ�����ָ��
//������2��NewImageBase���µ�ImageBase(�Լ��趨��
//������ֵ��BOOL ���ɹ�����TRUE��ʧ�ܷ���FALSE
VOID RestoreRelocation2(IN PCHAR pFileBuffer, IN DWORD NewImageBase)
{
	//--------------------------1.��ȡ�ļ�����ĸ��ֻ�ַ---------------------------------------------
	PIMAGE_DOS_HEADER      pDosHeader_Base = NULL;             //DOSͷ��ַ
	PIMAGE_NT_HEADERS      pNTHeader_Base = NULL;              //NTͷ��ַ
	PIMAGE_FILE_HEADER     pFileHeader_Base = NULL;            //�ļ�ͷ��ַ
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = NULL;          //��ѡͷ��ַ

	//1.��ȡDOSͷ��ַ(�����ļ�����Ļ�ַ��
	pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	//2.��ȡNTͷ��ַ�����ļ�����Ļ�ַƫ��e_lfanew�ľ���)
	pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	//3.��ȡ�ļ�ͷ��ַ
	pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.��ȡ��ѡͷ��ַ����ѡͷ�������ļ�ͷĩβ,���Կ�ѡͷ��ַ=�ļ�ͷ��ַ+�ļ�ͷ��С��	
	pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));

	//--------------------------2.��ȡ�ض�λ��Ļ�ַ---------------------------------------------
	//1.��ȡ�ض�λ���ַ��RVA
	DWORD pRelocationBase_RVA = pOptionHeader_Base->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	//2.�жϸ�PE�ļ��Ƿ����ض�λ��
	if (!pRelocationBase_RVA)
	{
		printf("��PE�ļ��������ض�λ������Ҫ�޸� \r\n");
		return ;
	}
	//3.��ȡ�ض�λ�����ļ������еĻ�ַ
	PIMAGE_BASE_RELOCATION pRelocationBlock_Base = (PIMAGE_BASE_RELOCATION)((PUCHAR)pFileBuffer + RvaToFoa(pFileBuffer, pRelocationBase_RVA));


	//-------------------------------3.����¾ɾ����ַ�Ĳ�ֵ�����������ַ----------------------------------------------------
	//1.����¾ɾ����ַ�Ĳ�ֵ(���ã�
	DWORD ImageBase_Sub = NewImageBase - pOptionHeader_Base->ImageBase;
	//2.���������ַ
	pOptionHeader_Base->ImageBase = NewImageBase;


	//--------------------------4.�޸��ض�λ��---------------------------------------------
	//1.ѭ������ֱ���ṹ��VirtualAddress-SizeOfBlock��ΪNULL
	DWORD dwCount = 1;
	while (pRelocationBlock_Base->VirtualAddress && pRelocationBlock_Base->SizeOfBlock)
	{
		//1.��ȡ��ǰ�ض�λ��Ļ�ַ(RVA���ͣ�
		DWORD pRelocationBlockBase_RVA = pRelocationBlock_Base->VirtualAddress;
		//2.��ȡ��ǰ�ض�λ��Ĵ�С
		DWORD pRelocationBlock_Size = pRelocationBlock_Base->SizeOfBlock;
		//3.��ȡ�ض�λ����Ļ�ַ(�ض�λ�������ض�λ���ַ����ƫ��8���ֽڴ���
		PWORD pRelData_Base = (PWORD)pRelocationBlock_Base + 8;
		//4.��ȡ�ض�λ�����ڵ�Ԫ�ظ���
		DWORD dwRelNumber = (pRelocationBlock_Base->SizeOfBlock - 8) / 2;
		//5.ѭ���޸��ض�λ�����е�Ԫ�أ�ÿ��Ԫ�ض���16λ��ȣ�
		for (size_t i = 0; i < dwRelNumber; i++)
		{
			//5.1 ��ȡ��4λ��ֵ
			WORD dwHigh_4 = (pRelData_Base[i] & 0xF000) >> 12;
			//5.2��ȡ��12λ��ֵ
			WORD dwLow_12 = pRelData_Base[i] & 0xFFF;
			//5.3 ��ȡ��Ҫ�޸���ֵ��RVA���ͣ�  //��Ҫ�޸���ֵ =��12λ��ֵ+ VirtualAddress
			DWORD dwDataRVA = dwLow_12 + pRelocationBlockBase_RVA;
			//5.4 ��ȡ��Ҫ�޸���ֵ��FOA���ͣ�
			DWORD dwDataFOA = RvaToFoa(pFileBuffer, dwDataRVA);
			//5.5��ȡ��Ҫ�޸���ֵ�Ļ�ַ�����ļ������е�λ�ã�
			PDWORD pData = PDWORD((DWORD)pFileBuffer + dwDataFOA);       
			//5.6�޸���Ҫ�ض�λ��Ԫ��
			if (dwHigh_4 == 3)
			{
				*pData = *pData + ImageBase_Sub;
			}
		}
		//6.���ض�λ��Ļ�ַָ����һ���ض�λ��
		pRelocationBlock_Base = (PIMAGE_BASE_RELOCATION)((PCHAR)pRelocationBlock_Base + pRelocationBlock_Base->SizeOfBlock);
	}

}


//����װ������EnableDebugPrivilege���������̷�������Ȩ��
//������ֵ��BOOL���ɹ�����TRUE��ʧ�ܷ���FALSE  
BOOL EnableDebugPrivilege()
{
	HANDLE hToken = NULL;
	//����Ȩ�޽ṹ��
	TOKEN_PRIVILEGES tp;

	//1.�򿪽������Ʋ���ȡ�������ƾ��
	BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (FALSE == bRet)
	{
		MessageBoxA(NULL,"�򿪽�������ʧ�ܣ�", NULL, NULL);
		return FALSE;
	}
	//2.��ȡ����ϵͳ�� pszPrivilegesName ��Ȩ��LUIDֵ��ŵ�tp�ṹ��
	bRet = LookupPrivilegeValue(NULL,SE_DEBUG_NAME, &tp.Privileges[0].Luid);
	if (FALSE == bRet)
	{
		MessageBoxA(NULL,"��ȡLUIDֵʧ�ܣ�", NULL, NULL);
		CloseHandle(hToken);
		hToken = INVALID_HANDLE_VALUE;
		return FALSE;
	}
	//3.��tp�ṹ���Ա���и�ֵ
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	//5.���޸ĺ��tp�ṹ��д�����������
	bRet = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

	//6.AdjustTokenPrivileges����FALSE��˵���޸�ʧ��
	if (FALSE == bRet)
	{
		MessageBoxA(NULL,"�����������Ʒ���Ȩ��ʧ�ܣ�", NULL, NULL);
		CloseHandle(hToken);
		hToken = INVALID_HANDLE_VALUE;
		return FALSE;
	}
	//6.AdjustTokenPrivileges����TRUE������������Ȩ���óɹ�������Ҫʹ��GetLastError���жϴ����뷵��ֵ
	else
	{
		//���ݴ������ж��Ƿ�����Ȩ�����óɹ�
		DWORD dwRet = GetLastError();
		//6.1�����뷵��ֵΪERROR_SUCCESS�����ʾ������Ȩ���óɹ�
		if (ERROR_SUCCESS == dwRet)
		{
			CloseHandle(hToken);
			hToken = INVALID_HANDLE_VALUE;
			return TRUE;
		}
		//6.2��ΪERROR_NOT_ALL_ASSIGNED�����ʾ������������Ȩ�����óɹ�
		else if (ERROR_NOT_ALL_ASSIGNED == dwRet)
		{
			MessageBoxA(NULL,"����Ȩ��ʧ�ܣ������Թ���Ա�������", NULL, NULL);
			CloseHandle(hToken);
			hToken = INVALID_HANDLE_VALUE;
			return FALSE;
		}
		else
		{
			MessageBoxA(NULL, "����Ȩ��ʧ�ܣ�", NULL, NULL);
			CloseHandle(hToken);
			hToken = INVALID_HANDLE_VALUE;
			return FALSE;
		}
	}
}


//����װ������GetPidByName��ͨ����������ȡ����PID
//������1��szProcessName��������
//������ֵ��DWORD ������PID
DWORD GetPidByName(IN const char* szProcessName)
{
	//1.��ʼ�����̽ṹ��
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	//2.��ȡ���̿��վ��
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshotʧ��\n");
		return -1;
	}
	//3.�������̿���
	BOOL bRet = Process32First(hSnap, &pe32);
	while (bRet)
	{
		//���ͨ���������Աȷ�����ͬ������
		if (strcmp(pe32.szExeFile, szProcessName) == 0)
		{
			printf("Process Name: %s ��PIDΪ: %d\n", pe32.szExeFile, pe32.th32ProcessID);
			//�رս��̿��վ��
			CloseHandle(hSnap);
			//���ؽ���PID���˳�
			return pe32.th32ProcessID;
		}
		//���ͨ���������Ա�û�з�����ͬ��������������һ������
		bRet = Process32Next(hSnap, &pe32);
	}
	//4.���ȫ�����̶�û���ҵ����ϵģ��رս��̿��վ��
	CloseHandle(hSnap);
	//5.����0��ʾû���ҵ����ϵĽ���
	return 0;
}

//����װ������Is32PEFile:��֤�Ƿ��ǺϷ���32λPE�ļ�
//������1��pFileBuffer:�ļ������ַ   //һ��ָ��
//������ֵ��BOOL�������32λPE�ļ�������TRUE��������ǣ�����FALSE
BOOL Is32PEFile(LPVOID pFileBuffer)
{
	//-------------------------------1.��λPE�ṹ���ֻ�ַ---------------------------------------------	
	//1.��ȡDOSͷ��ַ
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pFileBuffer;
	//2.��ȡNTͷ��ַ
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pFileBuffer + pDosHeader_Base->e_lfanew);
	//3.��ȡ�ļ�ͷ��ַ
	PIMAGE_FILE_HEADER pFileHeader_Base = PIMAGE_FILE_HEADER((PUCHAR)pNTHeader_Base + 4);
	//4.��ȡ��ѡͷ��ַ	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = PIMAGE_OPTIONAL_HEADER((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.��ȡ�ڱ�ͷ�����ַ
	PIMAGE_SECTION_HEADER pSectionHeaderGroup_Base = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader_Base + pFileHeader_Base->SizeOfOptionalHeader);

	//----------------------------------2.��ʼ�ж�
	if (pDosHeader_Base->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return FALSE;
	}
	if (pNTHeader_Base->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE���\n");
		return FALSE;
	}

	if (pOptionHeader_Base->Magic== 0x10b)  //0x10b  32   0x20b 64
	{
		printf("��32λ��PE�ļ�\n");
		return TRUE;
	}
	else if (pOptionHeader_Base->Magic == 0x20b)
	{
		printf("��64λ��PE�ļ�\n");
		return FALSE;
	}
	else
	{
		printf("δ֪λ����PE�ļ�\n");
		return FALSE;
	}
}

//����װ������GetAllThreadIdByProcessId�� ���� PID ��ȡ��ȡ�ý���ȫ���̵߳� TID
//������1��ProcessId �� ���� PID
//������2��pThreadId �� �������ڱ����߳�TID
//������3��ThreadIdLen �����ڷ�������ʵ�ʳ���
//������ֵ��BOOL���ɹ�����TRUE��ʧ�ܷ���FALSE
BOOL GetAllThreadIdByProcessId(IN ULONG ProcessId, IN ULONG* pThreadId, OUT ULONG* ThreadIdLen)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	ULONG Number = 0;

	// �������߳���һ������
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// ��ʹ�� Thread32First ǰ��ʼ�� THREADENTRY32 �Ľṹ��С.
	te32.dwSize = sizeof(THREADENTRY32);

	// ���ڻ�ȡϵͳ�߳��б�, ����ʾ��ָ��������ص�ÿ���̵߳���Ϣ
	do {
		// �ȶ��Ƿ�Ϊ�ý����߳�
		if (te32.th32OwnerProcessID == ProcessId)
		{
			// �ǵĻ����浽�߳�������
			pThreadId[Number] = te32.th32ThreadID;
			Number++;
		}
	} while (Thread32Next(hThreadSnap, &te32));

	if (!Number)
		return FALSE;
	// �޸��߳�����
	*ThreadIdLen = Number;
	return TRUE;
}


//����װ������RestoreIAT���޸�IAT��
//������1��pImageBuffer:���񻺴�ָ��  //һ��ָ��
//������ֵ��BOOL���ɹ�����TRUE��ʧ�ܷ���FALSE
BOOL RestoreIAT(IN PCHAR pImageBuffer)
{
	//-----------------------------------1.��λPE�ṹ���ֻ�ַ---------------------------------------------
	//1.��ȡDOSͷ��ַ(�����ļ�����Ļ�ַ��
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pImageBuffer;
	//2.��ȡNTͷ��ַ
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pImageBuffer + pDosHeader_Base->e_lfanew);
	//3.��ȡ�ļ�ͷ��ַ
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.��ȡ��ѡͷ��ַ	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));
	//5.��ȡ������ַƫ�ƣ�RVA���ͣ�
	DWORD pImport_Base_RVA = pOptionHeader_Base->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	//�жϸ�PE�ļ��Ƿ��е����
	if (!pImport_Base_RVA)
	{
		printf("��PE�ļ������ڵ���� \r\n");
		return FALSE;
	}
	//6.��ȡ������ھ��񻺴��еĻ�ַ
	PIMAGE_IMPORT_DESCRIPTOR pImport_Base = PIMAGE_IMPORT_DESCRIPTOR((PUCHAR)pImageBuffer + pImport_Base_RVA);

	//-----------------------------------------2.�޸�IAT��---------------------------------------------------
	//ѭ������
	while (pImport_Base->Name)
	{
		//1.��ȡ������ģ����
		PUCHAR pDllName = PUCHAR((DWORD)pImageBuffer + pImport_Base->Name);
		//2.��ȡ�����Ķ�Ӧģ��Ļ�ַ
		HMODULE hModule = LoadLibraryA((LPCSTR)pDllName);
		if (!hModule)
		{
			return FALSE;
		}
		//3.��ȡ������INT���ַ
		PDWORD pINT = (PDWORD)((PUCHAR)pImageBuffer + pImport_Base->OriginalFirstThunk);
		//4.��ȡ������IAT���ַ
		PDWORD pIAT = (PDWORD)((PUCHAR)pImageBuffer + pImport_Base->FirstThunk);

		//5.ѭ����ȡ������ַ��������IAT����
		do
		{
			//1.���庯����ַ����
			DWORD  dwFunAddr = 0;
			//2.������λ��ֵ
			DWORD  HIGH_1 = (*pINT) >> 31;
			//3.��õ�31λ��ֵ
			DWORD LOW_31 = (*pINT) & 0x7FFFFFFF;

			//4.������λΪ1����ôINT���ڵ�31λ��ŵ��Ǻ������
			if (HIGH_1)
			{
				//1.��ú�����Ŷ�Ӧ�ĺ�����ַ
				dwFunAddr = (DWORD)GetProcAddress(hModule, (LPCSTR)LOW_31);
			}
			//4.������λΪ0��INT���ڴ�ŵ���IMPORT_BY_NAME�ṹ���RVAֵ
			else
			{
				//1.��ȡIMPORT_BY_NAME�ṹ���ھ��񻺴��еĻ�ַ
				PIMAGE_IMPORT_BY_NAME pTemp = PIMAGE_IMPORT_BY_NAME((PUCHAR)pImageBuffer + *pINT);
				//2.���IMPORT_BY_NAME�ṹ���Name��Ա
				LPCSTR pname = pTemp->Name;
				//3.���Name��Ӧ�ĺ�����ַ
				dwFunAddr = (DWORD)GetProcAddress(hModule, pname);
			}
			//5.�����õĺ�����ַΪ�գ���˵���Ѿ���ȡ��β���������
			if (!dwFunAddr)
			{
				return FALSE;
			}
			//6.����IAT����ĺ�����ַ
			*pIAT = dwFunAddr;
			//7.����ָ����һ��INT��IAT
			pINT++;
			pIAT++;

		} while (*pINT);

		//6.ָ����һ�������ṹ
		pImport_Base++;
	}

	return TRUE;
}


//����װ������MemGetFunctionAddrByName��ͨ�����������ҵ���������ַ����Ե��Ƕ���Ĩ��PEָ�Ƶ�DLL��
//������1��pImageBuffer:���񻺴�ָ��  //һ��ָ��
//������2��szName��������
//������3��g_Exp :�������ַ������Ĩ��PEָ��֮ǰ�������һ��ȫ�ֱ�����
//������ֵ�������ĵ�ַ
PVOID MemGetFunctionAddrByName(IN PCHAR pImageBuffer, IN PCHAR szName,IN PCHAR g_Exp)
{
	//��Ϊ���DLL�������Լ����صģ�����ϵͳ���صģ����Բ���ȥexe�ĵ�������Һ�����ַ
	//���ǿ���ȥ���ص����DLL�ĵ��������Һ�����ַ
	//���Ҫ��дDLLʱһ��Ҫ����õ���������������

	//1.��λDLL�ĵ�ַ���ַ,���Ʊ��ַ,��ű��ַ
	PIMAGE_EXPORT_DIRECTORY ExportBase = (PIMAGE_EXPORT_DIRECTORY)g_Exp;
	LPDWORD pAddFunc = (LPDWORD)((DWORD)pImageBuffer + ExportBase->AddressOfFunctions);
	LPDWORD pAddName = (LPDWORD)((DWORD)pImageBuffer + ExportBase->AddressOfNames);
	LPWORD pAddOrdi = (LPWORD)((DWORD)pImageBuffer + ExportBase->AddressOfNameOrdinals);

	//2.����DLL�ĵ������ȡ������������ַ
	for (size_t i = 0; i < ExportBase->NumberOfNames; i++)
	{
		//1.������Ʊ����ĳһ�����������RVA��
		DWORD pname_RVA = pAddName[i];
		//2.������Ʊ����ĳһ���ھ��񻺴��еĻ�ַ����ַ�����ŵ��Ǻ������ַ�����
		PCHAR pname_Base = PCHAR((PUCHAR)pImageBuffer + pname_RVA);
		//3.�Աȴ������ĺ����������Ʊ���ĺ�����
		if (strcmp(szName, pname_Base) == 0)
		{
			//ע�⣺3�ű��˳�������Ʊ�-->��ű�--->��ַ��
			//ע�⣺���Ʊ��ڵ�ֵ��RVA����ű��ڵ�ֵ����ţ���ַ���ڵ�ֵ��RVA
			//ע�⣺���Ʊ��ڵĺ�������һ���Ա���ͬ����Ҫ�ѵ�ǰ�±���Ϊ��ű���±꣬����ű���ͬ�±�����ֵ
			//ע�⣺��ű�����ֵ��Ϊ�±�ȥ��ַ���ڲ��ң���һ������ݾ��Ǻ�����ַ��RVA��

			//1.���ŵ�ǰ�±�ȥ��ű�������ͬ�±����
			DWORD pnumber = pAddOrdi[i];
			//2.����ű����õ�����һ���������Ϊ�±�ȥ��ַ�����
			DWORD pAdd = pAddFunc[pnumber];
			//3.��ַ����鵽��ֵ+ImageBaseΪ����������ַ
			PVOID funcadd = PVOID((PUCHAR)pImageBuffer + pAdd);
			//4.������������ַ��Ϊ����ֵ���ݳ�ȥ
			return funcadd;
		}
	}
	return NULL;
}

//����װ������MemGetFunctionAddrByOrdinals��ͨ������������Ų��Һ�����ַ����Ե��Ƕ���Ĩ��PEָ�Ƶ�DLL��
//������1��pImageBuffer:���񻺴�ָ��  //һ��ָ��
//������2��dwOrdinal���������
//������3��g_Exp :�������ַ������Ĩ��PEָ��֮ǰ�������һ��ȫ�ֱ�����
//������ֵ�������ĵ�ַ
PVOID MemGetFunctionAddrByOrdinals(PCHAR pImageBuffer, DWORD dwOrdinal, IN PCHAR g_Exp)
{
	//1.��λ��ַ��,���Ʊ�,��ű�
	PIMAGE_EXPORT_DIRECTORY ExportBase = (PIMAGE_EXPORT_DIRECTORY)g_Exp;
	LPDWORD pAddFunc = (LPDWORD)(pImageBuffer + ExportBase->AddressOfFunctions);
	//2.�ж�����Ƿ���Ч
	if (dwOrdinal - ExportBase->Base > ExportBase->NumberOfFunctions)
	{
		return NULL;
	}
	//3.����ż�ȥ��ŵ�base����ֵ��Ϊ�±�ȥ��ַ���ڲ���
	DWORD pAdd = pAddFunc[dwOrdinal - ExportBase->Base];
	//4.��ַ����鵽��ֵ+ImageBaseΪ����������ַ
	PVOID funcadd = PVOID((PUCHAR)pImageBuffer + pAdd);
	//5.������������ַ��Ϊ����ֵ���ݳ�ȥ
	return funcadd;
}


//����װ������ClaenPeInfo:Ĩ��PEָ��
//������1��pImageBuffer:���񻺴�ָ��  //һ��ָ��
//������2��g_Exp:ָ�򡰵������ַ����ָ��  //����ָ��
VOID ClaenPeInfo(IN PCHAR pImageBuffer,OUT PCHAR* g_Exp)
{
	//--------------------------1.��λPE�ṹ���ֻ�ַ---------------------------------------------
	//1.��ȡDOSͷ��ַ
	PIMAGE_DOS_HEADER pDosHeader_Base = (PIMAGE_DOS_HEADER)pImageBuffer;
	//2.��ȡNTͷ��ַ
	PIMAGE_NT_HEADERS pNTHeader_Base = PIMAGE_NT_HEADERS((PUCHAR)pImageBuffer + pDosHeader_Base->e_lfanew);
	//3.��ȡ�ļ�ͷ��ַ
	PIMAGE_FILE_HEADER pFileHeader_Base = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader_Base + 4);
	//4.��ȡ��ѡͷ��ַ	
	PIMAGE_OPTIONAL_HEADER pOptionHeader_Base = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFileHeader_Base + sizeof(IMAGE_FILE_HEADER));

	//-------------------------2.���ݵ�����Ļ�ַ��������õ������ڵĺ���Ҫ�õ���--------------------------------
	*g_Exp = PCHAR((PUCHAR)pImageBuffer + pOptionHeader_Base->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//--------------------------------------3.Ĩ��PEͷ--------------------------------------------------------
	memset(pImageBuffer, 0, pOptionHeader_Base->SectionAlignment);
}

//-----------------------------------------------------------------------------------------------------------------
//1.����ṹ��UNICODE_STRING
typedef struct _UNICODE_STRING
{
	USHORT Length;                                                          //0x0
	USHORT MaximumLength;                                                   //0x2
	WCHAR* Buffer;                                                          //0x4
}UNICODE_STRING, *PUNICODE_STRING;
//2.����ṹ��PEB_LDR_DATA
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
//3.����ṹ��LDR_DATA_TABLE_ENTRY
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

//����װ������HideModule������ģ��
//������1��szModuleName��ģ����
VOID HideModule(PCHAR szModuleName)
{
	//ע�⣺TEB-->PEB-->PEB_LDR_DATA-->PLDR_DATA_TABLE_ENTRY-->PLIST_ENTRY
	//--------------------------------1.��ȡ���ֻ�ַ---------------------------------------------
	//1.��ô�������ģ������ģ���ַ
	HMODULE hMod = GetModuleHandleA(szModuleName);
	//2.��ȡPEB_LDR_DATA�Ļ�ַ
	PPEB_LDR_DATA pLdr_Base = NULL;
	__asm
	{
		MOV EAX, FS: [0x30]
		MOV EAX, [EAX + 0xC]
		MOV pLdr_Base, EAX
	}
	//3.��ȡPEB_LDR_DATA�еĳ�ԱInLoadOrderModuleList�ĵ�ַ
	//ע�⣺InLoadOrderModuleList�Ǵ�ṹ��PEB_LDR_DATA�е�Ƕ�׽ṹ��
	//����pLdr_Base->InLoadOrderModuleListȡ��InLoadOrderModuleList�ṹ�壬Ȼ����&(pLdr_Base->InLoadOrderModuleList)ȡ��InLoadOrderModuleList�Ļ�ַ
	PLIST_ENTRY pInLoadOrderModuleList_Base = &(pLdr_Base->InLoadOrderModuleList);
	//4.�ѽṹ��InLoadOrderModuleList�еĳ�ԱFlinkָ���ָ����Ϊ��һ��˫������Ļ�ַ
	PLIST_ENTRY FirstList_Base = pInLoadOrderModuleList_Base->Flink;
	//5.�ѵ�һ��˫������Ļ�ַ��Ϊ��ǰ˫������Ļ�ַ
	PLIST_ENTRY pCurrentList_Base = FirstList_Base;
	//6.�ӵ�ǰ˫������ʼ������ѯģ�飬�鵽���ϵľͶ���
	do
	{
		//��Ϊ��ṹ��PLDR_DATA_TABLE_ENTRY��Ƕ��С�ṹ��PLIST_ENTRY�����պ�Ƕ����ͷ�����������ߵĻ�ַ����ͬ��
		//1.��PLIST_ENTRY�Ļ�ַ����PLDR_DATA_TABLE_ENTRY
		PLDR_DATA_TABLE_ENTRY pCurrentLDREntry_Base = (PLDR_DATA_TABLE_ENTRY)pCurrentList_Base;
		//2.������ݽ�����ģ��ĵ�ַ�뵱ǰģ��ĵ�ַ��ͬ����ô���ж�������
		if (hMod == pCurrentLDREntry_Base->DllBase)
		{
			//���ĵ�1����
			pCurrentLDREntry_Base->InLoadOrderLinks.Blink->Flink = pCurrentLDREntry_Base->InLoadOrderLinks.Flink;
			pCurrentLDREntry_Base->InLoadOrderLinks.Flink->Blink = pCurrentLDREntry_Base->InLoadOrderLinks.Blink;

			//���ĵ�2����
			pCurrentLDREntry_Base->InMemoryOrderLinks.Blink->Flink = pCurrentLDREntry_Base->InMemoryOrderLinks.Flink;
			pCurrentLDREntry_Base->InMemoryOrderLinks.Flink->Blink = pCurrentLDREntry_Base->InMemoryOrderLinks.Blink;

			//���ĵ�3����
			pCurrentLDREntry_Base->InInitializationOrderLinks.Blink->Flink = pCurrentLDREntry_Base->InInitializationOrderLinks.Flink;
			pCurrentLDREntry_Base->InInitializationOrderLinks.Flink->Blink = pCurrentLDREntry_Base->InInitializationOrderLinks.Blink;

			//�޸��ڴ�����
			DWORD dwOldProct = 0;
			VirtualProtect(pCurrentLDREntry_Base->DllBase, 0x1000, PAGE_READWRITE, &dwOldProct);
			//Ĩ��PEָ��
			memset(pCurrentLDREntry_Base->DllBase, 0, 0x1000);
			//�ָ��ڴ�����
			VirtualProtect(pCurrentLDREntry_Base->DllBase, 0x1000, dwOldProct, NULL);

			break;
		}
		//3.ָ��ӵ�ǰ��˫�������Ƶ���һλ		
		pCurrentList_Base = pCurrentList_Base->Flink;

	} while (FirstList_Base != pCurrentList_Base);
}
//------------------------------------------------------------------------------------------------------------------------