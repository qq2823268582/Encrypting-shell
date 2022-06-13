#pragma once
DWORD Align(IN DWORD size, IN DWORD ALIGN_BASE);
BOOL FileToBuffer(IN PCHAR FilePath, OUT DWORD* FileSize, OUT PCHAR* pFileBuffer);
DWORD RvaToFoa(IN PCHAR pFileBuffer, IN DWORD RVA);
DWORD FoaToRva(IN PCHAR pFileBuffer, IN DWORD FOA);
BOOL AddOneSectionHead(IN PCHAR pFileBuffer, IN DWORD NewSectionSize, OUT DWORD* NewFileSize, OUT PCHAR* pNewFileBuffer);
BOOL BufferToFile(IN PCHAR FilePath, IN DWORD FileSize, IN PCHAR pFileBuffer);
VOID Encryption(IN PCHAR pFileBuffer, IN DWORD FileSize);
BOOL CopyLastSection(IN PCHAR pFileBuffer, OUT PCHAR* pNewBuffer, OUT DWORD* Newsize);
BOOL Decryption(IN PCHAR pFileBuffer, IN DWORD FileSize);
BOOL FileBufferToImageBuffer(IN PCHAR pFileBuffer, OUT PCHAR* pImageBuffer);
BOOL RestoreRelocation(IN PCHAR pImageBuffer);
BOOL EnableDebugPrivilege();