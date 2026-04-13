---
title: "Finding Module Address through PEB"
date: 2026-04-07 18:00
categories: [malware, windows-internals]
tags: [peb, process-environment-block]
---

## Introduction
Generally, programs resolve specific module addresses (such as kernel32.dll) by calling windows api like [GetModuleHandle()](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) or through native api like [NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation). However, this leaves alot of traces and can be easily detected by EDRs or by simplying analysing the Import Address Table (IAT) in the PE strucuture of the binary program. To stay stealthy, malware devs resolve module addresses through PEB walk.

## What is PEB?
When we execute a program, _TEB and _PEB structures are initalised by the kernel. 

- TEB (Thread Environment Block): A Structure that stores information specific to a thread

``` 
typedef struct _TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;
```
- PEB (Process Environment Block): A structure that contains information about the entire process, including loaded modules.

```
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

## Viewing Structures with WinDbg

Let's verify these structures by opening a process in WinDbg

(Please note that the below images will only show the relevant fields and not all fields)
```
dt _teb
```
![dt _teb](/assets/img/post1/1.PNG)

This command displays the ```_TEB``` structure. Take note of
```ProcessEnvironmentBlock``` field of which points to the ```_PEB```. In a 64 bit architecture, the offset is 0x060 and In 32 bit, it is 0x030.

```
dt _PEB
```
![dt _peb](/assets/img/post1/2.PNG)

This command display the structure of ```_PEB``` which has ```Ldr``` field which points to  ```_PEB_LDR_DATA``` structure.

```
dt _PEB_LDR_DATA
```
![dt _PEB_LDR_DATA](/assets/img/post1/3.PNG)

The ```_PEB_LDR_DATA``` structure contains ```InLoadOrderModuleList```, ```InMemoryOrderModuleList```, ```InInitializationOrderModuleList```. We will focus on ``InMemoryOrderModuleList``, which the head of a doubly linked list that contains the loaded modules of the process. Each item in the list is a pointer to an ```LDR_DATA_TABLE_ENTRY``` structure.
```
dt _LDR_DATA_TABLE_ENTRY
```
![dt _LDR_DATA_TABLE_ENTRY](/assets/img/post1/4.PNG)

This command display the stucture of ```_LDR_DATA_TABLE_ENTRY``` which is a linked list. This structure holds ```DllBase```(the base address of the loaded DLL) and the ```FullDllName```, ```BaseDllName```. These are teh values we need for a PEB walk. Take note of ```InMemoryOrderLinks``` field's offset at 0x010. We will come back to it later. 

## PEB Walk in WinDBG

```
! _peb
```
![! _peb](/assets/img/post1/5.PNG)

This command will display the current PEB information of the process running. Take note of loaded Dlls. At this moment, we are only interested in ```Ldr``` address, which is ```00007ffd5ac1c4c0```.

```
dt _PEB_LDR_DATA 00007ffd5ac1c4c0
```
![dt _PEB_LDR_DATA 00007ffd5ac1c4c0](/assets/img/post1/6.PNG)

This display the ```_PEB_LDR_DATA``` of our current process. What intersts us is the ```InMemoryOrderModuleList``` address. This address points directly to the ```InMemoryOrderLinks``` field inside the ```_LDR_DATA_TABLE_ENTRY``` structure.

To view the very start of ```_LDR_DATA_TABLE_ENTRY``` structure properly, we can take the address ```0x00000244ed3``` and substract by 0x10 (the offset of ```InMemoryOrderLinks```, see structure ```_LDR_DATA_TABLE_ENTRY``` for more details)

```
dt _LDR_DATA_TABLE_ENTRY 0x00000244ed3-10
```
![dt _LDR_DATA_TABLE_ENTRY 0x00000244ed3-10](/assets/img/post1/7.PNG)

Perfect, now we can see ```FullDllName```, ```BaseDllName``` and ```DllBase``` which is what we want. Currently the ```BaseDllName``` is ```helloworld.exe``` which is the executable of our process. 

We will continue to navigate ```Flink``` pointer inside ```InMemoryOrderLinks``` and subtract ```0x10``` to get the loaded modules. 

```
dt _LDR_DATA_TABLE_ENTRY 0x00000244ed4b2f30-10
```

![dt _LDR_DATA_TABLE_ENTRY 0x00000244ed4b2f30-10](/assets/img/post1/8.PNG)

Now the ```BaseDllName``` is ```ntdll.dll```.

```
dt _LDR_DATA_TABLE_ENTRY 0x00000244ed4b37b0-10
```
![dt _LDR_DATA_TABLE_ENTRY 0x00000244ed4b37b0-10](/assets/img/post1/9.PNG)

Next the ```BaseDllname``` is ```kernel32.dll``` which is our generally the common goal for malwares.

```
dt _LDR_DATA_TABLE_ENTRY 0x00000244ed4b3e90-10
```
![dt _LDR_DATA_TABLE_ENTRY 0x00000244ed4b3e90-10](/assets/img/post1/10.PNG)

Continuing the peb walk, we get ```BaseDllName``` ```kernelbase.dll```

```
dt _LDR_DATA_TABLE_ENTRY 0x00000244ed4b6ad0-10
```

![dt _LDR_DATA_TABLE_ENTRY 0x00000244ed4b6ad0-10](/assets/img/post1/11.PNG)

At the end we get, ```msvcrt.dll```

### Visual Recap
![Visual recap](/assets/img/post1/12.PNG)


## Resources
- <https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress>
- <https://learn.microsoft.com/de-de/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation>
- <https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb>
- <https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb>
- <https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data>
- <https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/>
- <https://github.com/cocomelonc/mdmz_book/blob/main/mdmz2/11-windows-shellcoding-2.md>
- <https://fareedfauzi.github.io/2024/07/13/PEB-Walk.html>
