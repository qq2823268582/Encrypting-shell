#pragma once
DWORD GetPidByName(IN const char* szProcessName);
BOOL Is32PEFile(LPVOID pFileBuffer);
DWORD Align(IN DWORD size, IN DWORD ALIGN_BASE);
BOOL EnableDebugPrivilege();
BOOL GetAllThreadIdByProcessId(IN ULONG ProcessId, IN ULONG* pThreadId, OUT ULONG* ThreadIdLen);
BOOL FileToBuffer(IN PCHAR FilePath, OUT DWORD* FileSize, OUT PCHAR* pFileBuffer);
DWORD RvaToFoa(IN PCHAR pFileBuffer, IN DWORD RVA);
DWORD FoaToRva(IN PCHAR pFileBuffer, IN DWORD FOA);
BOOL AddOneSectionHead(IN PCHAR pFileBuffer, IN DWORD NewSectionSize, OUT DWORD* NewFileSize, OUT PCHAR* pNewFileBuffer);
BOOL BufferToFile(IN PCHAR FilePath, IN DWORD FileSize, IN PCHAR pFileBuffer);
BOOL CopyLastSection(IN PCHAR pFileBuffer, OUT PCHAR* pNewBuffer, OUT DWORD* Newsize);
BOOL FileBufferToImageBuffer(IN PCHAR pFileBuffer, OUT PCHAR* pImageBuffer);
VOID RestoreRelocation1(IN PCHAR pImageBuffer);
VOID RestoreRelocation2(IN PCHAR pFileBuffer, IN DWORD NewImageBase);
BOOL RestoreIAT(IN PCHAR pImageBuffer);
PVOID MemGetFunctionAddrByName(IN PCHAR pImageBuffer, IN PCHAR szName, IN PCHAR g_Exp);
PVOID MemGetFunctionAddrByOrdinals(PCHAR pImageBuffer, DWORD dwOrdinal, IN PCHAR g_Exp);
VOID ClaenPeInfo(IN PCHAR pImageBuffer, OUT PCHAR* g_Exp);
VOID HideModule(PCHAR szModuleName);

VOID Encryption(IN PCHAR pFileBuffer, IN DWORD FileSize);
BOOL Decryption(IN PCHAR pFileBuffer, IN DWORD FileSize);