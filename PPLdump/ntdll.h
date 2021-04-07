/*****************************************************************************/
/* Ntdll.h                                Copyright (c) Ladislav Zezula 2005 */
/*---------------------------------------------------------------------------*/
/* Header file for the import library "Ntdll.lib"                            */
/*                                                                           */
/* This library has been created because of never-ending problems when       */
/* Ntdll.lib from Windows DDK with SDK libs (duplicate symbols, linker       */
/* errors etc).                                                              */
/* Now, it is possible to use native NT API with no problems, all you need   */
/* is just to include this header file                                       */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 15.05.03  1.00  Lad  The first version of Ntdll.h                         */
/* 16.09.05  2.00  Lad  Far more functions                                   */
/*****************************************************************************/

#include <Windows.h>

#ifndef __NTDLL_H__
#define __NTDLL_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _NTDDK_
#error This header cannot be compiled together with NTDDK
#endif

#ifndef _NTDLL_SELF_                            // Auto-insert the library
#pragma comment(lib, "Ntdll.lib")
#endif

#pragma warning(disable: 4201)                  // nonstandard extension used : nameless struct/union

//------------------------------------------------------------------------------
// Defines for NTSTATUS

#ifdef _Return_type_success_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
#else
typedef LONG NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)   ((NTSTATUS)(Status) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL  ((NTSTATUS)0xC0000001L)
#endif

#ifndef ASSERT
#ifdef _DEBUG
#define ASSERT(x) assert(x)
#else
#define ASSERT(x) /* x */
#endif
#endif

#ifndef DEVICE_TYPE
#define DEVICE_TYPE DWORD
#endif

//-----------------------------------------------------------------------------
// Definition of intervals for waiting functions

#define ABSOLUTE_INTERVAL(wait) (wait)

#define RELATIVE_INTERVAL(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILISECONDS(mili) \
(((signed __int64)(mili)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILISECONDS(1000L))

//------------------------------------------------------------------------------
// Structures

#ifndef _NTDEF_
typedef enum _EVENT_TYPE
{
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

//
// ANSI strings are counted 8-bit character strings. If they are
// NULL terminated, Length does not include trailing NULL.
//

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} STRING, *PSTRING;

//
// Unicode strings are counted 16-bit character strings. If they are
// NULL terminated, Length does not include trailing NULL.
//

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

//
// bitmap type
//

typedef struct _RTL_BITMAP
{
    ULONG SizeOfBitmap;
    PULONG Buffer;
} RTL_BITMAP, *PRTL_BITMAP;

//
// preallocated heap-growable buffers
//

typedef struct _RTL_BUFFER
{
    PUCHAR    Buffer;
    PUCHAR    StaticBuffer;
    SIZE_T    Size;
    SIZE_T    StaticSize;
    SIZE_T    ReservedForAllocatedSize;     // for future doubling
    PVOID     ReservedForIMalloc;           // for future pluggable growth
} RTL_BUFFER, *PRTL_BUFFER;

//
// A preallocated buffer that is "tied" to a UNICODE_STRING
//

typedef struct _RTL_UNICODE_STRING_BUFFER
{
    UNICODE_STRING String;
    RTL_BUFFER     ByteBuffer;
    UCHAR          MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];

} RTL_UNICODE_STRING_BUFFER, *PRTL_UNICODE_STRING_BUFFER;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;

typedef const UNICODE_STRING *PCUNICODE_STRING;

#define UNICODE_NULL ((WCHAR)0) // winnt

#ifndef RTL_CONSTANT_STRING         // UNICODE_STRING FooStr = RTL_CONSTANT_STRING(L"Foo");
#define RTL_CONSTANT_STRING(str)    {(USHORT)(sizeof(str) - sizeof(str[0])), (USHORT)(sizeof(str)), str}
#endif  // RTL_CONSTANT_STRING

//
// Definitions for Object Creation
//

#define OBJ_INHERIT                             0x00000002L
#define OBJ_PERMANENT                           0x00000010L
#define OBJ_EXCLUSIVE                           0x00000020L
#define OBJ_CASE_INSENSITIVE                    0x00000040L
#define OBJ_OPENIF                              0x00000080L
#define OBJ_OPENLINK                            0x00000100L
#define OBJ_KERNEL_HANDLE                       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK                  0x00000400L
#define OBJ_VALID_ATTRIBUTES                    0x000007F2L

//
// Object Attributes structure
//

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

//
// IO_STATUS_BLOCK
//

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };

    ULONG_PTR Information;

} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

//
// ClientId
//

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
#endif // _NTDEF_
/*
typedef struct _IMAGE_RELOC
{
    WORD offset : 12;
    WORD type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;
*/

//------------------------------------------------------------------------------
// Macros

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( innerPath, n, a, r, s ) {   \
    (innerPath)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (innerPath)->RootDirectory = r;                             \
    (innerPath)->Attributes = a;                                \
    (innerPath)->ObjectName = n;                                \
    (innerPath)->SecurityDescriptor = s;                        \
    (innerPath)->SecurityQualityOfService = NULL;               \
    }
#endif

//
// Macros for handling LIST_ENTRY-based lists
//

#if !defined(_WDMDDK_) && !defined(_LIST_ENTRY_MACROS_DEFINED_)
#define _LIST_ENTRY_MACROS_DEFINED_

BOOLEAN
FORCEINLINE
IsListEmpty(
    IN const LIST_ENTRY * ListHead
    )
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
VOID
InitializeListHead(
    IN PLIST_ENTRY ListHead
    )
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

FORCEINLINE
VOID
InsertHeadList(
    IN OUT PLIST_ENTRY ListHead,
    IN OUT PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Flink;

    Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}

FORCEINLINE
VOID
InsertTailList(
    IN OUT PLIST_ENTRY ListHead,
    IN OUT PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

FORCEINLINE
BOOLEAN
RemoveEntryList(
    IN PLIST_ENTRY Entry
    )
{
    PLIST_ENTRY Blink;
    PLIST_ENTRY Flink;

    Flink = Entry->Flink;
    Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}
#endif  // #if !defined(_WDMDDK_) && !defined(_LIST_ENTRY_MACROS_DEFINED_)

//-----------------------------------------------------------------------------
// Bitmap functions

NTSYSAPI
VOID
NTAPI
RtlSetBit(
    PRTL_BITMAP BitMapHeader,
    ULONG BitNumber
    );

NTSYSAPI
VOID
NTAPI
RtlSetBits(
    PRTL_BITMAP BitMapHeader,
    ULONG StartingIndex,
    ULONG NumberToSet
    );

//-----------------------------------------------------------------------------
// Unicode string functions

NTSYSAPI
VOID
NTAPI
RtlInitString(
    PSTRING DestinationString,
    PCSTR SourceString
    );

NTSYSAPI
VOID
NTAPI
RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlInitUnicodeStringEx(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlCreateUnicodeString(
    OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlCreateUnicodeStringFromAsciiz(
    OUT PUNICODE_STRING Destination,
    IN PCSTR Source
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlPrefixUnicodeString(
    IN PUNICODE_STRING String1,
    IN PUNICODE_STRING String2,
    IN BOOLEAN CaseInSensitive
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlDuplicateUnicodeString(
    IN  BOOLEAN AllocateNew,
    IN  PUNICODE_STRING SourceString,
    OUT PUNICODE_STRING TargetString
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlAppendUnicodeToString(
    PUNICODE_STRING Destination,
    PCWSTR Source
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlAppendUnicodeStringToString(
    IN OUT PUNICODE_STRING Destination,
    IN PUNICODE_STRING Source
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToInteger(
    IN PUNICODE_STRING String,
    IN ULONG Base OPTIONAL,
    OUT PULONG Value
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlIntegerToUnicodeString(
    IN ULONG Value,
    IN ULONG Base OPTIONAL,
    IN OUT PUNICODE_STRING String
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlGUIDFromString(
    IN PUNICODE_STRING GuidString,
    OUT GUID *Guid
    );

NTSYSAPI
LONG
NTAPI
RtlCompareUnicodeString(
    IN PUNICODE_STRING String1,
    IN PUNICODE_STRING String2,
    IN BOOLEAN CaseInSensitive
    );

// Windows Vista or newer
NTSYSAPI
LONG
NTAPI
RtlCompareUnicodeStrings(
    IN PWCH String1,
    IN SIZE_T Length1,
    IN PWCH String2,
    IN SIZE_T Length2,
    IN BOOLEAN CaseInSensitive
    );

NTSYSAPI
VOID
NTAPI
RtlCopyUnicodeString(
    OUT PUNICODE_STRING DestinationString,
    IN PUNICODE_STRING SourceString
    );

NTSYSAPI
WCHAR
NTAPI
RtlUpcaseUnicodeChar(
    IN WCHAR SourceCharacter
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeString(
    OUT PUNICODE_STRING DestinationString,
    IN PUNICODE_STRING SourceString,
    IN BOOLEAN AllocateDestinationString
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlDowncaseUnicodeString(
    OUT PUNICODE_STRING DestinationString,
    IN PUNICODE_STRING SourceString,
    IN BOOLEAN AllocateDestinationString
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlUpcaseUnicodeToMultiByteN(
    OUT PCH MultiByteString,
    IN ULONG MaxBytesInMultiByteString,
    OUT PULONG BytesInMultiByteString OPTIONAL,
    IN PWCH UnicodeString,
    IN ULONG BytesInUnicodeString
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlEqualUnicodeString(
    IN PUNICODE_STRING String1,
    IN PUNICODE_STRING String2,
    IN BOOLEAN CaseInSensitive
    );

NTSYSAPI
VOID
NTAPI
RtlFreeUnicodeString(
    IN  PUNICODE_STRING UnicodeString
    );

NTSYSAPI
WCHAR
NTAPI
RtlAnsiCharToUnicodeChar(
    IN OUT PUCHAR * SourceCharacter
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlAnsiStringToUnicodeString(
    OUT PUNICODE_STRING DestinationString,
    IN PANSI_STRING SourceString,
    IN BOOLEAN AllocateDestinationString
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeStringToAnsiString(
    OUT PANSI_STRING DestinationString,
    IN PUNICODE_STRING SourceString,
    IN BOOLEAN AllocateDestinationString
    );

NTSYSAPI
VOID
NTAPI
RtlInitAnsiString(
    OUT PANSI_STRING DestinationString,
    IN PCHAR SourceString
    );

NTSYSAPI
VOID
NTAPI
RtlFreeAnsiString(
    IN PANSI_STRING AnsiString
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlFormatCurrentUserKeyPath(
    OUT PUNICODE_STRING CurrentUserKeyPath
    );

NTSYSAPI
VOID
NTAPI
RtlRaiseStatus(
    IN NTSTATUS Status
    );

NTSYSAPI
VOID
NTAPI
DbgBreakPoint(
    VOID
    );

NTSYSAPI
ULONG
_cdecl
DbgPrint(
    PCH Format,
    ...
    );

// Since Windows XP
NTSYSAPI
ULONG
__cdecl
DbgPrintEx(
    IN ULONG ComponentId,
    IN ULONG Level,
    IN PCSTR Format,
    ...
    );

NTSYSAPI
ULONG
NTAPI
RtlRandom(
    IN OUT PULONG Seed
    );

//-----------------------------------------------------------------------------
// Critical section functions

NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeCriticalSection(
    IN  PRTL_CRITICAL_SECTION CriticalSection
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlInitializeCriticalSectionAndSpinCount(
    IN  PRTL_CRITICAL_SECTION CriticalSection,
    IN  ULONG SpinCount
    );

NTSYSAPI
BOOL
NTAPI
RtlTryEnterCriticalSection(
    IN PRTL_CRITICAL_SECTION CriticalSection
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlEnterCriticalSection(
    IN PRTL_CRITICAL_SECTION CriticalSection
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlLeaveCriticalSection(
    IN PRTL_CRITICAL_SECTION CriticalSection
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlDeleteCriticalSection(
    IN  PRTL_CRITICAL_SECTION CriticalSection
    );

//-----------------------------------------------------------------------------
// Compression and decompression

NTSYSAPI
NTSTATUS
NTAPI
RtlCompressBuffer(
    IN  USHORT CompressionFormatAndEngine,
    IN  PUCHAR UncompressedBuffer,
    IN  ULONG UncompressedBufferSize,
    OUT PUCHAR CompressedBuffer,
    IN  ULONG CompressedBufferSize,
    IN  ULONG UncompressedChunkSize,
    OUT PULONG FinalCompressedSize,
    IN  PVOID WorkSpace
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlDecompressBuffer(
    IN  USHORT CompressionFormat,
    OUT PUCHAR UncompressedBuffer,
    IN  ULONG UncompressedBufferSize,
    IN  PUCHAR CompressedBuffer,
    IN  ULONG CompressedBufferSize,
    OUT PULONG FinalUncompressedSize
    );

//-----------------------------------------------------------------------------
// 8.3 name support

typedef struct _GENERATE_NAME_CONTEXT
{
    //
    //  The structure is divided into two strings.  The Name, and extension.
    //  Each part contains the value that was last inserted in the name.
    //  The length values are in terms of wchars and not bytes.  We also
    //  store the last index value used in the generation collision algorithm.
    //

    USHORT Checksum;
    BOOLEAN ChecksumInserted;

    UCHAR NameLength;                             // not including extension
    WCHAR NameBuffer[8];                          // e.g., "ntoskrnl"

    ULONG ExtensionLength;                        // including dot
    WCHAR ExtensionBuffer[4];                     // e.g., ".exe"

    ULONG LastIndexValue;

} GENERATE_NAME_CONTEXT, *PGENERATE_NAME_CONTEXT;

NTSYSAPI
BOOLEAN
NTAPI
RtlIsNameLegalDOS8Dot3(
    IN PUNICODE_STRING Name,
    IN OUT POEM_STRING OemName OPTIONAL,
    OUT PBOOLEAN NameContainsSpaces OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlGenerate8dot3Name (
    IN PCUNICODE_STRING Name,
    IN BOOLEAN AllowExtendedCharacters,
    IN OUT PGENERATE_NAME_CONTEXT Context,
    IN OUT PUNICODE_STRING Name8dot3
    );

//-----------------------------------------------------------------------------
// Object functions

//
// Object Manager Directory Specific Access Rights.
//

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY                         0x0001
#define DIRECTORY_TRAVERSE                      0x0002
#define DIRECTORY_CREATE_OBJECT                 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY           0x0008
#define DIRECTORY_ALL_ACCESS                    (STANDARD_RIGHTS_REQUIRED | 0xF)
#endif

typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS,
    MaxPoolType,
    NonPagedPoolSession = 32,
    PagedPoolSession,
    NonPagedPoolMustSucceedSession,
    DontUseThisTypeSession,
    NonPagedPoolCacheAlignedSession,
    PagedPoolCacheAlignedSession,
    NonPagedPoolCacheAlignedMustSSession

} POOL_TYPE;


//
// For NtQueryObject
//

typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectTypesInformation,
    ObjectHandleFlagInformation,
    ObjectSessionInformation,
    MaxObjectInfoClass

} OBJECT_INFORMATION_CLASS;

//
// NtQueryObject uses ObjectBasicInformation
//

typedef struct _OBJECT_BASIC_INFORMATION
{
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
    ULONG Reserved[3];
    ULONG NameInformationLength;
    ULONG TypeInformationLength;
    ULONG SecurityDescriptorLength;
    LARGE_INTEGER CreateTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

//
// NtQueryObject uses ObjectNameInformation
//

typedef struct _OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

//
// NtQueryObject uses ObjectTypeInformation
//

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPES_INFORMATION
{
    ULONG NumberOfTypes;
    OBJECT_TYPE_INFORMATION TypeInformation[1];
} OBJECT_TYPES_INFORMATION, *POBJECT_TYPES_INFORMATION;

//
// NtQueryObject uses ObjectHandleFlagInformation
// NtSetInformationObject uses ObjectHandleFlagInformation
//

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION
{
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, *POBJECT_HANDLE_FLAG_INFORMATION;

//
// NtQueryDirectoryObject uses this type
//

typedef struct _OBJECT_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateDirectoryObject(
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenDirectoryObject(
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryDirectoryObject(
    IN HANDLE DirectoryHandle,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN BOOLEAN ReturnSingleEntry,
    IN BOOLEAN RestartScan,
    IN OUT PULONG Context,
    OUT PULONG ReturnLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryObject (
    IN HANDLE ObjectHandle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG Length,
    OUT PULONG ResultLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationObject (
    IN HANDLE ObjectHandle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    IN PVOID ObjectInformation,
    IN ULONG Length
    );

NTSYSAPI
NTSTATUS
NTAPI
NtDuplicateObject (
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle OPTIONAL,
    OUT PHANDLE TargetHandle OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Options
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySecurityObject (
    IN HANDLE ObjectHandle,
    IN SECURITY_INFORMATION SecurityInformation,
    OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN ULONG DescriptorLength,
    OUT PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySecurityObject (
    IN HANDLE ObjectHandle,
    IN SECURITY_INFORMATION SecurityInformation,
    OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN ULONG DescriptorLength,
    OUT PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetSecurityObject (
    IN HANDLE ObjectHandle,
    IN SECURITY_INFORMATION SecurityInformation,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwSetSecurityObject (
    IN HANDLE ObjectHandle,
    IN SECURITY_INFORMATION SecurityInformation,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor
    );

NTSYSAPI
NTSTATUS
NTAPI
NtMakeTemporaryObject(
    IN HANDLE ObjectHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwMakeTemporaryObject(
    IN HANDLE ObjectHandle
    );

//-----------------------------------------------------------------------------
// Handle table RTL functions

#define LEVEL_HANDLE_ID         0x74000000
#define LEVEL_HANDLE_ID_MASK    0xFF000000
#define LEVEL_HANDLE_INDEX_MASK 0x00FFFFFF

typedef enum _RTL_GENERIC_COMPARE_RESULTS
{
    GenericLessThan,
    GenericGreaterThan,
    GenericEqual
} RTL_GENERIC_COMPARE_RESULTS;


typedef struct _RTL_SPLAY_LINKS
{
    struct _RTL_SPLAY_LINKS *Parent;
    struct _RTL_SPLAY_LINKS *LeftChild;
    struct _RTL_SPLAY_LINKS *RightChild;
} RTL_SPLAY_LINKS, *PRTL_SPLAY_LINKS;


struct _RTL_GENERIC_TABLE;

typedef
RTL_GENERIC_COMPARE_RESULTS
(NTAPI * PRTL_GENERIC_COMPARE_ROUTINE) (
    struct _RTL_GENERIC_TABLE *Table,
    PVOID FirstStruct,
    PVOID SecondStruct
    );

typedef
PVOID
(NTAPI *PRTL_GENERIC_ALLOCATE_ROUTINE) (
    struct _RTL_GENERIC_TABLE *Table,
    ULONG ByteSize
    );

typedef
VOID
(NTAPI *PRTL_GENERIC_FREE_ROUTINE) (
    struct _RTL_GENERIC_TABLE *Table,
    PVOID Buffer
    );


typedef struct _RTL_GENERIC_TABLE
{
    PRTL_SPLAY_LINKS TableRoot;
    LIST_ENTRY InsertOrderList;
    PLIST_ENTRY OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    PRTL_GENERIC_COMPARE_ROUTINE CompareRoutine;
    PRTL_GENERIC_ALLOCATE_ROUTINE AllocateRoutine;
    PRTL_GENERIC_FREE_ROUTINE FreeRoutine;
    PVOID TableContext;
} RTL_GENERIC_TABLE, *PRTL_GENERIC_TABLE;


typedef struct _RTL_HANDLE_TABLE_ENTRY
{
    ULONG Flags;
    struct _RTL_HANDLE_TABLE_ENTRY *NextFree;
} RTL_HANDLE_TABLE_ENTRY, *PRTL_HANDLE_TABLE_ENTRY;


typedef struct _RTL_HANDLE_TABLE
{
    ULONG MaximumNumberOfHandles;
    ULONG SizeOfHandleTableEntry;
    ULONG Reserved[2];
    PRTL_HANDLE_TABLE_ENTRY FreeHandles;
    PRTL_HANDLE_TABLE_ENTRY CommittedHandles;
    PRTL_HANDLE_TABLE_ENTRY UnCommittedHandles;
    PRTL_HANDLE_TABLE_ENTRY MaxReservedHandles;
} RTL_HANDLE_TABLE, *PRTL_HANDLE_TABLE;

NTSYSAPI
VOID
NTAPI
RtlInitializeGenericTable (
    IN PRTL_GENERIC_TABLE Table,
    IN PRTL_GENERIC_COMPARE_ROUTINE CompareRoutine,
    IN PRTL_GENERIC_ALLOCATE_ROUTINE AllocateRoutine,
    IN PRTL_GENERIC_FREE_ROUTINE FreeRoutine,
    IN PVOID TableContext
    );

NTSYSAPI
VOID
NTAPI
RtlInitializeHandleTable(
    IN ULONG MaximumNumberOfHandles,
    IN ULONG SizeOfHandleTableEntry,
    OUT PRTL_HANDLE_TABLE HandleTable
    );

NTSYSAPI
PRTL_HANDLE_TABLE_ENTRY
NTAPI
RtlAllocateHandle(
    IN PRTL_HANDLE_TABLE HandleTable,
    OUT PULONG HandleIndex OPTIONAL
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHandle(
    IN PRTL_HANDLE_TABLE HandleTable,
    IN PRTL_HANDLE_TABLE_ENTRY Handle
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlIsValidIndexHandle(
    IN PRTL_HANDLE_TABLE HandleTable,
    IN ULONG HandleIndex,
    OUT PRTL_HANDLE_TABLE_ENTRY *Handle
    );

NTSYSAPI
PVOID
NTAPI
RtlInsertElementGenericTable (
    IN PRTL_GENERIC_TABLE Table,
    IN PVOID Buffer,
    IN LONG BufferSize,
    OUT PBOOLEAN NewElement OPTIONAL
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlIsGenericTableEmpty (
    IN PRTL_GENERIC_TABLE Table
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlIsGenericTableEmpty (
    IN PRTL_GENERIC_TABLE Table
    );

NTSYSAPI
PVOID
NTAPI
RtlLookupElementGenericTable (
    IN PRTL_GENERIC_TABLE Table,
    IN PVOID Buffer
    );

NTSYSAPI
PVOID
NTAPI
RtlEnumerateGenericTableWithoutSplaying(
    IN  PRTL_GENERIC_TABLE Table,
    IN  PVOID *RestartKey
    );

NTSYSAPI
NTSTATUS
NTAPI
NtClose(
    IN  HANDLE Handle
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwClose(
    IN  HANDLE Handle
    );

//-----------------------------------------------------------------------------
// Environment functions

NTSYSAPI
NTSTATUS
NTAPI
RtlOpenCurrentUser(
    IN ULONG DesiredAccess,
    OUT PHANDLE CurrentUserKey
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateEnvironment(
    BOOLEAN CloneCurrentEnvironment,
    PVOID *Environment
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlExpandEnvironmentStrings_U(
    IN PVOID Environment OPTIONAL,
    IN PUNICODE_STRING Source,
    OUT PUNICODE_STRING Destination,
    OUT PULONG ReturnedLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryEnvironmentVariable_U(
    IN PVOID Environment,
    IN PUNICODE_STRING Name,
    OUT PUNICODE_STRING Value
    );

NTSYSAPI
ULONG
NTAPI
RtlDosSearchPath_U(
    IN PCWSTR lpPath,
    IN PCWSTR lpFileName,
    IN PCWSTR lpExtension OPTIONAL,
    IN ULONG nBufferLength,
    OUT PWSTR lpBuffer,
    OUT PWSTR *lpFilePart
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlSetEnvironmentVariable(
    PVOID *Environment,
    PUNICODE_STRING Name,
    PUNICODE_STRING Value
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyEnvironment(
    PVOID Environment
    );

//-----------------------------------------------------------------------------
// Registry functions

typedef enum _KEY_INFORMATION_CLASS
{
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation

} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS
{
    KeyValueBasicInformation = 0,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64
} KEY_VALUE_INFORMATION_CLASS;

typedef enum _KEY_SET_INFORMATION_CLASS
{
    KeyWriteTimeInformation,
    KeyUserFlagsInformation,
    MaxKeySetInfoClass
} KEY_SET_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _KEY_NODE_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NODE_INFORMATION, *PKEY_NODE_INFORMATION;

typedef struct _KEY_FULL_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG ClassOffset;
    ULONG ClassLength;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG MaxClassLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    WCHAR Class[1];
} KEY_FULL_INFORMATION, *PKEY_FULL_INFORMATION;

typedef struct _KEY_NAME_INFORMATION
{
    WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef struct _KEY_CACHED_INFORMATION
{
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG SubKeys;
    ULONG MaxNameLen;
    ULONG Values;
    ULONG MaxValueNameLen;
    ULONG MaxValueDataLen;
    ULONG NameLength;
    WCHAR Name[1];            // Variable length string
} KEY_CACHED_INFORMATION, *PKEY_CACHED_INFORMATION;

typedef struct _KEY_FLAGS_INFORMATION
{
    ULONG   UserFlags;
} KEY_FLAGS_INFORMATION, *PKEY_FLAGS_INFORMATION;

typedef struct _KEY_VALUE_BASIC_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;
    ULONG DataLength;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION
{
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtLoadKey(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile
    );

NTSYSAPI
NTSTATUS
NTAPI
NtLoadKey2(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile,
    IN ULONG Flags
    );

// NtLoadKeyEx for Windows 2003 server
typedef NTSTATUS (NTAPI * NTLOADKEYEX_3790)(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile,
    IN ULONG Flags,
    IN HANDLE TrustClassKey OPTIONAL
    );

// NtLoadKeyEx for Windows Vista to Windows 8.1
typedef NTSTATUS (NTAPI * NTLOADKEYEX)(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile,
    IN ULONG Flags,
    IN HANDLE TrustClassKey OPTIONAL,
    IN PVOID Param5,
    IN PVOID Param6,
    IN PVOID Param7,
    IN PVOID Param8
    );

NTSYSAPI
NTSTATUS
NTAPI
NtUnloadKey(
    IN POBJECT_ATTRIBUTES TargetKey
    );

NTSYSAPI
NTSTATUS
NTAPI
NtCreateKey(
    OUT PHANDLE KeyHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  ULONG TitleIndex,
    IN  PUNICODE_STRING Class OPTIONAL,
    IN  ULONG CreateOptions,
    OUT PULONG Disposition OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
NtEnumerateKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    IN PVOID KeyInformation,
    IN ULONG Length,
    IN PULONG ResultLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwEnumerateKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    IN PVOID KeyInformation,
    IN ULONG Length,
    IN PULONG ResultLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtEnumerateValueKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT PVOID  KeyValueInformation,
    IN  ULONG  Length,
    OUT PULONG  ResultLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwEnumerateValueKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT PVOID  KeyValueInformation,
    IN  ULONG  Length,
    OUT PULONG  ResultLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtDeleteKey(
    IN HANDLE KeyHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryKey(
    IN  HANDLE KeyHandle,
    IN  KEY_INFORMATION_CLASS KeyInformationClass,
    OUT PVOID KeyInformation OPTIONAL,
    IN  ULONG Length,
    OUT PULONG ResultLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT PVOID KeyValueInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN ULONG TitleIndex OPTIONAL,
    IN ULONG Type,
    IN PVOID Data,
    IN ULONG DataSize
    );

NTSYSAPI
NTSTATUS
NTAPI
NtDeleteValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName
    );

NTSYSAPI
NTSTATUS
NTAPI
NtFlushKey(
    IN HANDLE KeyHandle
    );

//-----------------------------------------------------------------------------
// RtlQueryRegistryValues

//
// The following flags specify how the Name field of a RTL_QUERY_REGISTRY_TABLE
// entry is interpreted.  A NULL name indicates the end of the table.
//

#define RTL_QUERY_REGISTRY_SUBKEY   0x00000001  // Name is a subkey and remainder of
                                                // table or until next subkey are value
                                                // names for that subkey to look at.

#define RTL_QUERY_REGISTRY_TOPKEY   0x00000002  // Reset current key to original key for
                                                // this and all following table entries.

#define RTL_QUERY_REGISTRY_REQUIRED 0x00000004  // Fail if no match found for this table
                                                // entry.

#define RTL_QUERY_REGISTRY_NOVALUE  0x00000008  // Used to mark a table entry that has no
                                                // value name, just wants a call out, not
                                                // an enumeration of all values.

#define RTL_QUERY_REGISTRY_NOEXPAND 0x00000010  // Used to suppress the expansion of
                                                // REG_MULTI_SZ into multiple callouts or
                                                // to prevent the expansion of environment
                                                // variable values in REG_EXPAND_SZ

#define RTL_QUERY_REGISTRY_DIRECT   0x00000020  // QueryRoutine field ignored.  EntryContext
                                                // field points to location to store value.
                                                // For null terminated strings, EntryContext
                                                // points to UNICODE_STRING structure that
                                                // that describes maximum size of buffer.
                                                // If .Buffer field is NULL then a buffer is
                                                // allocated.
                                                //

#define RTL_QUERY_REGISTRY_DELETE   0x00000040  // Used to delete value keys after they
                                                // are queried.


//
// The following values for the RelativeTo parameter determine what the
// Path parameter to RtlQueryRegistryValues is relative to.
//

#define RTL_REGISTRY_ABSOLUTE     0             // Path is an absolute registry path.
#define RTL_REGISTRY_SERVICES     1             // Path is relative to \Registry\Machine\System\CurrentControlSet\Services
#define RTL_REGISTRY_CONTROL      2             // Path is relative to \Registry\Machine\System\CurrentControlSet\Control
#define RTL_REGISTRY_WINDOWS_NT   3             // Path is relative to \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
#define RTL_REGISTRY_DEVICEMAP    4             // Path is relative to \Registry\Machine\Hardware\DeviceMap
#define RTL_REGISTRY_USER         5             // Path is relative to \Registry\User\CurrentUser. (For a system process, this is \User\.Default)
#define RTL_REGISTRY_MAXIMUM      6
#define RTL_REGISTRY_HANDLE       0x40000000    // Specifies that the Path parameter is actually a registry handle to use
#define RTL_REGISTRY_OPTIONAL     0x80000000    // Specifies that the key referenced by this parameter and the Path parameter are optional


typedef NTSTATUS (NTAPI * PRTL_QUERY_REGISTRY_ROUTINE)(
    IN PWSTR ValueName,
    IN ULONG ValueType,
    IN PVOID ValueData,
    IN ULONG ValueLength,
    IN PVOID Context,
    IN PVOID EntryContext
    );

typedef struct _RTL_QUERY_REGISTRY_TABLE
{
    PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
    ULONG Flags;
    PWSTR Name;
    PVOID EntryContext;
    ULONG DefaultType;
    PVOID DefaultData;
    ULONG DefaultLength;
} RTL_QUERY_REGISTRY_TABLE, *PRTL_QUERY_REGISTRY_TABLE;

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryRegistryValues(
    IN ULONG  RelativeTo,
    IN PCWSTR  Path,
    IN PRTL_QUERY_REGISTRY_TABLE  QueryTable,
    IN PVOID  Context,
    IN PVOID  Environment OPTIONAL
    );


//-----------------------------------------------------------------------------
// Query system information

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,                     // 0x00
    SystemProcessorInformation,                 // 0x01
    SystemPerformanceInformation,               // 0x02
    SystemTimeOfDayInformation,                 // 0x03
    SystemPathInformation,                      // 0x04 (Obsolete: Use KUSER_SHARED_DATA)
    SystemProcessInformation,                   // 0x05
    SystemCallCountInformation,                 // 0x06
    SystemDeviceInformation,                    // 0x07
    SystemProcessorPerformanceInformation,      // 0x08
    SystemFlagsInformation,                     // 0x09
    SystemCallTimeInformation,                  // 0x0a
    SystemModuleInformation,                    // 0x0b
    SystemLocksInformation,                     // 0x0c
    SystemStackTraceInformation,                // 0x0d
    SystemPagedPoolInformation,                 // 0x0e
    SystemNonPagedPoolInformation,              // 0x0f
    SystemHandleInformation,                    // 0x10
    SystemObjectInformation,                    // 0x11
    SystemPageFileInformation,                  // 0x12
    SystemVdmInstemulInformation,               // 0x13
    SystemVdmBopInformation,                    // 0x14
    SystemFileCacheInformation,                 // 0x15
    SystemPoolTagInformation,                   // 0x16
    SystemInterruptInformation,                 // 0x17
    SystemDpcBehaviorInformation,               // 0x18
    SystemFullMemoryInformation,                // 0x19
    SystemLoadGdiDriverInformation,             // 0x1a
    SystemUnloadGdiDriverInformation,           // 0x1b
    SystemTimeAdjustmentInformation,            // 0x1c
    SystemSummaryMemoryInformation,             // 0x1d
    SystemMirrorMemoryInformation,              // 0x1e
    SystemPerformanceTraceInformation,          // 0x1f
    SystemObsolete0,                            // 0x20
    SystemExceptionInformation,                 // 0x21
    SystemCrashDumpStateInformation,            // 0x22
    SystemKernelDebuggerInformation,            // 0x23
    SystemContextSwitchInformation,             // 0x24
    SystemRegistryQuotaInformation,             // 0x25
    SystemExtendServiceTableInformation,        // 0x26
    SystemPrioritySeperation,                   // 0x27
    SystemPlugPlayBusInformation,               // 0x28
    SystemDockInformation,                      // 0x29
    SystemPowerInformationNative,               // 0x2a
    SystemProcessorSpeedInformation,            // 0x2b
    SystemCurrentTimeZoneInformation,           // 0x2c
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemAddVerifier,
    SystemSessionProcessesInformation,
    SystemLoadGdiDriverInSystemSpaceInformation,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchDogTimerHandler,
    SystemWatchDogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWo64SharedInformationObosolete,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    SystemThreadPriorityClientIdInformation,
    SystemProcessorIdleCycleTimeInformation,
    SystemVerifierCancellationInformation,
    SystemProcessorPowerInformationEx,
    SystemRefTraceInformation,
    SystemSpecialPoolInformation,
    SystemProcessIdInformation,
    SystemErrorPortInformation,
    SystemBootEnvironmentInformation,
    SystemHypervisorInformation,
    SystemVerifierInformationEx,
    SystemTimeZoneInformation,
    SystemImageFileExecutionOptionsInformation,
    SystemCoverageInformation,
    SystemPrefetchPathInformation,
    SystemVerifierFaultsInformation,
    MaxSystemInfoClass,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

//
// Thread priority
//

typedef LONG KPRIORITY;

//
// Information Structures for NtQuerySystemInformation
//
typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

// Class 1
typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    USHORT Reserved;
    ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

// Class 2
typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleProcessTime;
    LARGE_INTEGER IoReadTransferCount;
    LARGE_INTEGER IoWriteTransferCount;
    LARGE_INTEGER IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
    ULONG PageReadCount;
    ULONG PageReadIoCount;
    ULONG CacheReadCount;
    ULONG CacheIoCount;
    ULONG DirtyPagesWriteCount;
    ULONG DirtyWriteIoCount;
    ULONG MappedPagesWriteCount;
    ULONG MappedWriteIoCount;
    ULONG PagedPoolPages;
    ULONG NonPagedPoolPages;
    ULONG PagedPoolAllocs;
    ULONG PagedPoolFrees;
    ULONG NonPagedPoolAllocs;
    ULONG NonPagedPoolFrees;
    ULONG FreeSystemPtes;
    ULONG ResidentSystemCodePage;
    ULONG TotalSystemDriverPages;
    ULONG TotalSystemCodePages;
    ULONG NonPagedPoolLookasideHits;
    ULONG PagedPoolLookasideHits;
    ULONG Spare3Count;
    ULONG ResidentSystemCachePage;
    ULONG ResidentPagedPoolPage;
    ULONG ResidentSystemDriverPage;
    ULONG CcFastReadNoWait;
    ULONG CcFastReadWait;
    ULONG CcFastReadResourceMiss;
    ULONG CcFastReadNotPossible;
    ULONG CcFastMdlReadNoWait;
    ULONG CcFastMdlReadWait;
    ULONG CcFastMdlReadResourceMiss;
    ULONG CcFastMdlReadNotPossible;
    ULONG CcMapDataNoWait;
    ULONG CcMapDataWait;
    ULONG CcMapDataNoWaitMiss;
    ULONG CcMapDataWaitMiss;
    ULONG CcPinMappedDataCount;
    ULONG CcPinReadNoWait;
    ULONG CcPinReadWait;
    ULONG CcPinReadNoWaitMiss;
    ULONG CcPinReadWaitMiss;
    ULONG CcCopyReadNoWait;
    ULONG CcCopyReadWait;
    ULONG CcCopyReadNoWaitMiss;
    ULONG CcCopyReadWaitMiss;
    ULONG CcMdlReadNoWait;
    ULONG CcMdlReadWait;
    ULONG CcMdlReadNoWaitMiss;
    ULONG CcMdlReadWaitMiss;
    ULONG CcReadAheadIos;
    ULONG CcLazyWriteIos;
    ULONG CcLazyWritePages;
    ULONG CcDataFlushes;
    ULONG CcDataPages;
    ULONG ContextSwitches;
    ULONG FirstLevelTbFills;
    ULONG SecondLevelTbFills;
    ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

// Class 3
typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    ULONG TimeZoneId;
    ULONG Reserved;
    LARGE_INTEGER BootTimeBias;
    LARGE_INTEGER SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

// Class 4
// This class is obsolete, please use KUSER_SHARED_DATA instead

// Class 5
typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;

    //
    // This part corresponds to VM_COUNTERS_EX.
    // NOTE: *NOT* THE SAME AS VM_COUNTERS!
    //
    SIZE_T PeakVirtualSize;
    ULONG VirtualSize;
    SIZE_T PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;

    //
    // This part corresponds to IO_COUNTERS
    //
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;

    //SYSTEM_THREAD_INFORMATION TH[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// Class 6
typedef struct _SYSTEM_CALL_COUNT_INFORMATION
{
    ULONG Length;
    ULONG NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION;

// Class 7
typedef struct _SYSTEM_DEVICE_INFORMATION
{
    ULONG NumberOfDisks;
    ULONG NumberOfFloppies;
    ULONG NumberOfCdRoms;
    ULONG NumberOfTapes;
    ULONG NumberOfSerialPorts;
    ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, *PSYSTEM_DEVICE_INFORMATION;

// Class 8
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
    LARGE_INTEGER IdleTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER DpcTime;
    LARGE_INTEGER InterruptTime;
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

// Class 9
typedef struct _SYSTEM_FLAGS_INFORMATION
{
    ULONG Flags;
} SYSTEM_FLAGS_INFORMATION, *PSYSTEM_FLAGS_INFORMATION;

// Class 10
typedef struct _SYSTEM_CALL_TIME_INFORMATION
{
    ULONG Length;
    ULONG TotalCalls;
    LARGE_INTEGER TimeOfCalls[1];
} SYSTEM_CALL_TIME_INFORMATION, *PSYSTEM_CALL_TIME_INFORMATION;

// Class 11 - See RTL_PROCESS_MODULES
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    ULONG Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION, SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES, SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

// Class 12 - See RTL_PROCESS_LOCKS
typedef struct _RTL_PROCESS_LOCK_INFORMATION
{
    PVOID Address;
    USHORT Type;
    USHORT CreatorBackTraceIndex;
    ULONG OwnerThreadId;
    ULONG ActiveCount;
    ULONG ContentionCount;
    ULONG EntryCount;
    ULONG RecursionCount;
    ULONG NumberOfSharedWaiters;
    ULONG NumberOfExclusiveWaiters;
} RTL_PROCESS_LOCK_INFORMATION, *PRTL_PROCESS_LOCK_INFORMATION;

typedef struct _RTL_PROCESS_LOCKS
{
    ULONG NumberOfLocks;
    RTL_PROCESS_LOCK_INFORMATION Locks[1];
} RTL_PROCESS_LOCKS, *PRTL_PROCESS_LOCKS;

// Class 13 - See RTL_PROCESS_BACKTRACES
typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION
{
    PVOID SymbolicBackTrace;
    ULONG TraceCount;
    USHORT Index;
    USHORT Depth;
    PVOID BackTrace[16];
} RTL_PROCESS_BACKTRACE_INFORMATION, *PRTL_PROCESS_BACKTRACE_INFORMATION;

typedef struct _RTL_PROCESS_BACKTRACES
{
    ULONG CommittedMemory;
    ULONG ReservedMemory;
    ULONG NumberOfBackTraceLookups;
    ULONG NumberOfBackTraces;
    RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[1];
} RTL_PROCESS_BACKTRACES, *PRTL_PROCESS_BACKTRACES;

// Class 14 - 15
typedef struct _SYSTEM_POOL_ENTRY
{
    BOOLEAN Allocated;
    BOOLEAN Spare0;
    USHORT AllocatorBackTraceIndex;
    ULONG Size;
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
        PVOID ProcessChargedQuota;
    };
} SYSTEM_POOL_ENTRY, *PSYSTEM_POOL_ENTRY;

typedef struct _SYSTEM_POOL_INFORMATION
{
    ULONG TotalSize;
    PVOID FirstEntry;
    USHORT EntryOverhead;
    BOOLEAN PoolTagPresent;
    BOOLEAN Spare0;
    ULONG NumberOfEntries;
    SYSTEM_POOL_ENTRY Entries[1];
} SYSTEM_POOL_INFORMATION, *PSYSTEM_POOL_INFORMATION;

// Class 16
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// Class 17
typedef struct _SYSTEM_OBJECTTYPE_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfObjects;
    ULONG NumberOfHandles;
    ULONG TypeIndex;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    ULONG PoolType;
    BOOLEAN SecurityRequired;
    BOOLEAN WaitableObject;
    UNICODE_STRING TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, *PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION
{
    ULONG NextEntryOffset;
    PVOID Object;
    HANDLE CreatorUniqueProcess;
    USHORT CreatorBackTraceIndex;
    USHORT Flags;
    LONG PointerCount;
    LONG HandleCount;
    ULONG PagedPoolCharge;
    ULONG NonPagedPoolCharge;
    HANDLE ExclusiveProcessId;
    PVOID SecurityDescriptor;
    OBJECT_NAME_INFORMATION NameInfo;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

// Class 18
typedef struct _SYSTEM_PAGEFILE_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG TotalSize;
    ULONG TotalInUse;
    ULONG PeakUsage;
    UNICODE_STRING PageFileName;
} SYSTEM_PAGEFILE_INFORMATION, *PSYSTEM_PAGEFILE_INFORMATION;

// Class 19
typedef struct _SYSTEM_VDM_INSTEMUL_INFO
{
    ULONG SegmentNotPresent;
    ULONG VdmOpcode0F;
    ULONG OpcodeESPrefix;
    ULONG OpcodeCSPrefix;
    ULONG OpcodeSSPrefix;
    ULONG OpcodeDSPrefix;
    ULONG OpcodeFSPrefix;
    ULONG OpcodeGSPrefix;
    ULONG OpcodeOPER32Prefix;
    ULONG OpcodeADDR32Prefix;
    ULONG OpcodeINSB;
    ULONG OpcodeINSW;
    ULONG OpcodeOUTSB;
    ULONG OpcodeOUTSW;
    ULONG OpcodePUSHF;
    ULONG OpcodePOPF;
    ULONG OpcodeINTnn;
    ULONG OpcodeINTO;
    ULONG OpcodeIRET;
    ULONG OpcodeINBimm;
    ULONG OpcodeINWimm;
    ULONG OpcodeOUTBimm;
    ULONG OpcodeOUTWimm ;
    ULONG OpcodeINB;
    ULONG OpcodeINW;
    ULONG OpcodeOUTB;
    ULONG OpcodeOUTW;
    ULONG OpcodeLOCKPrefix;
    ULONG OpcodeREPNEPrefix;
    ULONG OpcodeREPPrefix;
    ULONG OpcodeHLT;
    ULONG OpcodeCLI;
    ULONG OpcodeSTI;
    ULONG BopCount;
} SYSTEM_VDM_INSTEMUL_INFO, *PSYSTEM_VDM_INSTEMUL_INFO;

// Class 20 - ULONG VDMBOPINFO

// Class 21
typedef struct _SYSTEM_FILECACHE_INFORMATION
{
    ULONG CurrentSize;
    ULONG PeakSize;
    ULONG PageFaultCount;
    ULONG MinimumWorkingSet;
    ULONG MaximumWorkingSet;
    ULONG CurrentSizeIncludingTransitionInPages;
    ULONG PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

// Class 22
typedef struct _SYSTEM_POOLTAG
{
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
    ULONG PagedAllocs;
    ULONG PagedFrees;
    ULONG PagedUsed;
    ULONG NonPagedAllocs;
    ULONG NonPagedFrees;
    ULONG NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;
typedef struct _SYSTEM_POOLTAG_INFORMATION
{
    ULONG Count;
    SYSTEM_POOLTAG TagInfo[1];
} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

// Class 23
typedef struct _SYSTEM_INTERRUPT_INFORMATION
{
    ULONG ContextSwitches;
    ULONG DpcCount;
    ULONG DpcRate;
    ULONG TimeIncrement;
    ULONG DpcBypassCount;
    ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION;

// Class 24
typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION
{
    ULONG Spare;
    ULONG DpcQueueDepth;
    ULONG MinimumDpcRate;
    ULONG AdjustDpcThreshold;
    ULONG IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, *PSYSTEM_DPC_BEHAVIOR_INFORMATION;

// Class 25
typedef struct _SYSTEM_MEMORY_INFO
{
    PUCHAR StringOffset;
    USHORT ValidCount;
    USHORT TransitionCount;
    USHORT ModifiedCount;
    USHORT PageTableCount;
} SYSTEM_MEMORY_INFO, *PSYSTEM_MEMORY_INFO;

typedef struct _SYSTEM_MEMORY_INFORMATION
{
    ULONG InfoSize;
    ULONG StringStart;
    SYSTEM_MEMORY_INFO Memory[1];
} SYSTEM_MEMORY_INFORMATION, *PSYSTEM_MEMORY_INFORMATION;

// Class 26
typedef struct _SYSTEM_GDI_DRIVER_INFORMATION
{
    UNICODE_STRING DriverName;
    PVOID ImageAddress;
    PVOID SectionPointer;
    PVOID EntryPoint;
    PIMAGE_EXPORT_DIRECTORY ExportSectionPointer;
    ULONG ImageLength;
} SYSTEM_GDI_DRIVER_INFORMATION, *PSYSTEM_GDI_DRIVER_INFORMATION;

// Class 27
// Not an actually class, simply a PVOID to the ImageAddress

// Class 28
typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    ULONG TimeIncrement;
    BOOLEAN Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, *PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION
{
    ULONG TimeAdjustment;
    BOOLEAN Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION, *PSYSTEM_SET_TIME_ADJUST_INFORMATION;

// Class 29 - Same as 25

// FIXME: Class 30

// Class 31
typedef struct _SYSTEM_REF_TRACE_INFORMATION
{
   UCHAR TraceEnable;
   UCHAR TracePermanent;
   UNICODE_STRING TraceProcessName;
   UNICODE_STRING TracePoolTags;
} SYSTEM_REF_TRACE_INFORMATION, *PSYSTEM_REF_TRACE_INFORMATION;

// Class 32 - OBSOLETE

// Class 33
typedef struct _SYSTEM_EXCEPTION_INFORMATION
{
    ULONG AlignmentFixupCount;
    ULONG ExceptionDispatchCount;
    ULONG FloatingEmulationCount;
    ULONG ByteWordEmulationCount;
} SYSTEM_EXCEPTION_INFORMATION, *PSYSTEM_EXCEPTION_INFORMATION;

// Class 34
typedef struct _SYSTEM_CRASH_STATE_INFORMATION
{
    ULONG ValidCrashDump;
} SYSTEM_CRASH_STATE_INFORMATION, *PSYSTEM_CRASH_STATE_INFORMATION;

// Class 35
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

// Class 36
typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION
{
    ULONG ContextSwitches;
    ULONG FindAny;
    ULONG FindLast;
    ULONG FindIdeal;
    ULONG IdleAny;
    ULONG IdleCurrent;
    ULONG IdleLast;
    ULONG IdleIdeal;
    ULONG PreemptAny;
    ULONG PreemptCurrent;
    ULONG PreemptLast;
    ULONG SwitchToIdle;
} SYSTEM_CONTEXT_SWITCH_INFORMATION, *PSYSTEM_CONTEXT_SWITCH_INFORMATION;

// Class 37
typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION
{
    ULONG RegistryQuotaAllowed;
    ULONG RegistryQuotaUsed;
    ULONG PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION;

// Class 38
// Not a structure, simply send the UNICODE_STRING

// Class 39
// Not a structure, simply send a ULONG containing the new separation

// Class 40
typedef struct _SYSTEM_PLUGPLAY_BUS_INFORMATION
{
    ULONG BusCount;
//  PLUGPLAY_BUS_INSTANCE BusInstance[1];
} SYSTEM_PLUGPLAY_BUS_INFORMATION, *PSYSTEM_PLUGPLAY_BUS_INFORMATION;

// Class 41
typedef enum _SYSTEM_DOCK_STATE
{
    SystemDockStateUnknown,
    SystemUndocked,
    SystemDocked
} SYSTEM_DOCK_STATE, *PSYSTEM_DOCK_STATE;

typedef enum _INTERFACE_TYPE
{
    InterfaceTypeUndefined = -1,
    Internal,
    Isa,
    Eisa,
    MicroChannel,
    TurboChannel,
    PCIBus,
    VMEBus,
    NuBus,
    PCMCIABus,
    CBus,
    MPIBus,
    MPSABus,
    ProcessorInternal,
    InternalPowerBus,
    PNPISABus,
    PNPBus,
    MaximumInterfaceType
}INTERFACE_TYPE, *PINTERFACE_TYPE;

typedef struct _SYSTEM_DOCK_INFORMATION
{
    SYSTEM_DOCK_STATE DockState;
    INTERFACE_TYPE DeviceBusType;
    ULONG DeviceBusNumber;
    ULONG SlotNumber;
} SYSTEM_DOCK_INFORMATION, *PSYSTEM_DOCK_INFORMATION;

// Class 42
typedef struct _SYSTEM_POWER_INFORMATION_NATIVE
{
    BOOLEAN SystemSuspendSupported;
    BOOLEAN SystemHibernateSupported;
    BOOLEAN ResumeTimerSupportsSuspend;
    BOOLEAN ResumeTimerSupportsHibernate;
    BOOLEAN LidSupported;
    BOOLEAN TurboSettingSupported;
    BOOLEAN TurboMode;
    BOOLEAN SystemAcOrDc;
    BOOLEAN PowerDownDisabled;
    LARGE_INTEGER SpindownDrives;
} SYSTEM_POWER_INFORMATION_NATIVE, *PSYSTEM_POWER_INFORMATION_NATIVE;

// Class 43
typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION
{
//  PNP_VETO_TYPE VetoType;
    UNICODE_STRING VetoDriver;
    // CHAR Buffer[0];
} SYSTEM_LEGACY_DRIVER_INFORMATION, *PSYSTEM_LEGACY_DRIVER_INFORMATION;

// Class 44
//typedef struct _TIME_ZONE_INFORMATION RTL_TIME_ZONE_INFORMATION;

// Class 45
typedef struct _SYSTEM_LOOKASIDE_INFORMATION
{
    USHORT CurrentDepth;
    USHORT MaximumDepth;
    ULONG TotalAllocates;
    ULONG AllocateMisses;
    ULONG TotalFrees;
    ULONG FreeMisses;
    ULONG Type;
    ULONG Tag;
    ULONG Size;
} SYSTEM_LOOKASIDE_INFORMATION, *PSYSTEM_LOOKASIDE_INFORMATION;

// Class 46
// Not a structure. Only a HANDLE for the SlipEvent;

// Class 47
// Not a structure. Only a ULONG for the SessionId;

// Class 48
// Not a structure. Only a ULONG for the SessionId;

// FIXME: Class 49

// Class 50
// Not a structure. Only a ULONG_PTR for the SystemRangeStart

// Class 51
typedef struct _SYSTEM_VERIFIER_INFORMATION
{
   ULONG NextEntryOffset;
   ULONG Level;
   UNICODE_STRING DriverName;
   ULONG RaiseIrqls;
   ULONG AcquireSpinLocks;
   ULONG SynchronizeExecutions;
   ULONG AllocationsAttempted;
   ULONG AllocationsSucceeded;
   ULONG AllocationsSucceededSpecialPool;
   ULONG AllocationsWithNoTag;
   ULONG TrimRequests;
   ULONG Trims;
   ULONG AllocationsFailed;
   ULONG AllocationsFailedDeliberately;
   ULONG Loads;
   ULONG Unloads;
   ULONG UnTrackedPool;
   ULONG CurrentPagedPoolAllocations;
   ULONG CurrentNonPagedPoolAllocations;
   ULONG PeakPagedPoolAllocations;
   ULONG PeakNonPagedPoolAllocations;
   ULONG PagedPoolUsageInBytes;
   ULONG NonPagedPoolUsageInBytes;
   ULONG PeakPagedPoolUsageInBytes;
   ULONG PeakNonPagedPoolUsageInBytes;
} SYSTEM_VERIFIER_INFORMATION, *PSYSTEM_VERIFIER_INFORMATION;

// FIXME: Class 52

// Class 53
typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
    ULONG SessionId;
    ULONG SizeOfBuf;
    PVOID Buffer; // Same format as in SystemProcessInformation
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

// FIXME: Class 54-97

//
// Hotpatch flags
//
#define RTL_HOTPATCH_SUPPORTED_FLAG         0x01
#define RTL_HOTPATCH_SWAP_OBJECT_NAMES      0x08 << 24
#define RTL_HOTPATCH_SYNC_RENAME_FILES      0x10 << 24
#define RTL_HOTPATCH_PATCH_USER_MODE        0x20 << 24
#define RTL_HOTPATCH_REMAP_SYSTEM_DLL       0x40 << 24
#define RTL_HOTPATCH_PATCH_KERNEL_MODE      0x80 << 24

// Class info 64
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG  HandleAttributes;
    ULONG  Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;


typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;


// Class 69
typedef struct _SYSTEM_HOTPATCH_CODE_INFORMATION
{
    ULONG Flags;
    ULONG InfoSize;
    union
    {
        struct
        {
            ULONG Foo;
        } CodeInfo;
        struct
        {
            USHORT NameOffset;
            USHORT NameLength;
        } KernelInfo;
        struct
        {
            USHORT NameOffset;
            USHORT NameLength;
            USHORT TargetNameOffset;
            USHORT TargetNameLength;
            UCHAR PatchingFinished;
        } UserModeInfo;
        struct
        {
            USHORT NameOffset;
            USHORT NameLength;
            USHORT TargetNameOffset;
            USHORT TargetNameLength;
            UCHAR PatchingFinished;
            NTSTATUS ReturnCode;
            HANDLE TargetProcess;
        } InjectionInfo;
        struct
        {
            HANDLE FileHandle1;
            PIO_STATUS_BLOCK IoStatusBlock1;
            PVOID RenameInformation1;
            PVOID RenameInformationLength1;
            HANDLE FileHandle2;
            PIO_STATUS_BLOCK IoStatusBlock2;
            PVOID RenameInformation2;
            PVOID RenameInformationLength2;
        } RenameInfo;
        struct
        {
            HANDLE ParentDirectory;
            HANDLE ObjectHandle1;
            HANDLE ObjectHandle2;
        } AtomicSwap;
    };
} SYSTEM_HOTPATCH_CODE_INFORMATION, *PSYSTEM_HOTPATCH_CODE_INFORMATION;

//
// Class 75
//
struct _SYSTEM_FIRMWARE_TABLE_INFORMATION;
typedef NTSTATUS (__cdecl *PFNFTH)(
    IN struct _SYSTEM_FIRMWARE_TABLE_INFORMATION *FirmwareTableInformation
    );

typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION
{
    SystemFirmwareTable_Enumerate = 0,
    SystemFirmwareTable_Get = 1,
} SYSTEM_FIRMWARE_TABLE_ACTION, *PSYSTEM_FIRMWARE_TABLE_ACTION;

typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER
{
    ULONG ProviderSignature;
    BOOLEAN Register;
    PFNFTH FirmwareTableHandler;
    PVOID DriverObject;
} SYSTEM_FIRMWARE_TABLE_HANDLER, *PSYSTEM_FIRMWARE_TABLE_HANDLER;

//
// Class 76
//
typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
{
    ULONG ProviderSignature;
    SYSTEM_FIRMWARE_TABLE_ACTION Action;
    ULONG TableID;
    ULONG TableBufferLength;
    UCHAR TableBuffer[1];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;

//
// Class 81
//
typedef struct _SYSTEM_MEMORY_LIST_INFORMATION
{
   SIZE_T ZeroPageCount;
   SIZE_T FreePageCount;
   SIZE_T ModifiedPageCount;
   SIZE_T ModifiedNoWritePageCount;
   SIZE_T BadPageCount;
   SIZE_T PageCountByPriority[8];
   SIZE_T RepurposedPagesByPriority[8];
} SYSTEM_MEMORY_LIST_INFORMATION, *PSYSTEM_MEMORY_LIST_INFORMATION;

//
// Class 88
//
typedef struct _SYSTEM_PROCESS_ID_INFORMATION
{
    HANDLE UniqueProcessId;                         // On input, set this to Process ID
    UNICODE_STRING ImageName;                       // On input, initialize to an allocated buffer
} SYSTEM_PROCESS_ID_INFORMATION, *PSYSTEM_PROCESS_ID_INFORMATION;

//
// Class 90
//
typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION
{
    GUID  CurrentBootGuid;
    ULONG Unknown;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, *PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;


typedef NTSTATUS (NTAPI * NTQUERYSYSTEMINFORMATION)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS (NTAPI * RTLGETNATIVESYSTEMINFORMATION)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
    );

typedef BOOLEAN (NTAPI * RTLGETPRODUCTINFO)(
    IN  ULONG OSMajorVersion,
    IN  ULONG OSMinorVersion,
    IN  ULONG SpMajorVersion,
    IN  ULONG SpMinorVersion,
    OUT PULONG ReturnedProductType
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetSystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN PVOID SystemInformation,
    IN ULONG SystemInformationLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwSetSystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN PVOID SystemInformation,
    IN ULONG SystemInformationLength
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlGetNativeSystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
    );

//------------------------------------------------------------------------------
// Shutdown system

typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff

} SHUTDOWN_ACTION, *PSHUTDOWN_ACTION;

NTSYSAPI
NTSTATUS
NTAPI
NtShutdownSystem(
    IN SHUTDOWN_ACTION Action
    );

//-----------------------------------------------------------------------------
// File functions

#ifndef OLD_DOS_VOLID
#define OLD_DOS_VOLID   0x00000008
#endif

#ifndef FILE_SUPERSEDE
#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005
#endif  // File create flags


// Define the create/open option flags
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080
#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_FOR_RECOVERY                  0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800
#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000
#define FILE_OPEN_REQUIRING_OPLOCK              0x00010000
#define FILE_DISALLOW_EXCLUSIVE                 0x00020000
#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000
#endif // FILE_DIRECTORY_FILE


//
// Define the I/O status information return values for NtCreateFile/NtOpenFile
//

#ifndef FILE_SUPERSEDED
#define FILE_SUPERSEDED                 0x00000000
#define FILE_OPENED                     0x00000001
#define FILE_CREATED                    0x00000002
#define FILE_OVERWRITTEN                0x00000003
#define FILE_EXISTS                     0x00000004
#define FILE_DOES_NOT_EXIST             0x00000005
#endif

#ifndef FILE_REMOVABLE_MEDIA
#define FILE_REMOVABLE_MEDIA                    0x00000001
#define FILE_READ_ONLY_DEVICE                   0x00000002
#define FILE_FLOPPY_DISKETTE                    0x00000004
#define FILE_WRITE_ONCE_MEDIA                   0x00000008
#define FILE_REMOTE_DEVICE                      0x00000010
#define FILE_DEVICE_IS_MOUNTED                  0x00000020
#define FILE_VIRTUAL_VOLUME                     0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME          0x00000080
#define FILE_DEVICE_SECURE_OPEN                 0x00000100
#define FILE_CHARACTERISTIC_PNP_DEVICE          0x00000800
#define FILE_CHARACTERISTIC_TS_DEVICE           0x00001000
#define FILE_CHARACTERISTIC_WEBDAV_DEVICE       0x00002000
#endif

#ifndef PIO_APC_ROUTINE_DEFINED
typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );
#define PIO_APC_ROUTINE_DEFINED
#endif  // PIO_APC_ROUTINE_DEFINED


typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation                 = 1,
    FileFullDirectoryInformation,            // 2
    FileBothDirectoryInformation,            // 3
    FileBasicInformation,                    // 4
    FileStandardInformation,                 // 5
    FileInternalInformation,                 // 6
    FileEaInformation,                       // 7
    FileAccessInformation,                   // 8
    FileNameInformation,                     // 9
    FileRenameInformation,                   // 10
    FileLinkInformation,                     // 11
    FileNamesInformation,                    // 12
    FileDispositionInformation,              // 13
    FilePositionInformation,                 // 14
    FileFullEaInformation,                   // 15
    FileModeInformation,                     // 16
    FileAlignmentInformation,                // 17
    FileAllInformation,                      // 18
    FileAllocationInformation,               // 19
    FileEndOfFileInformation,                // 20
    FileAlternateNameInformation,            // 21
    FileStreamInformation,                   // 22
    FilePipeInformation,                     // 23
    FilePipeLocalInformation,                // 24
    FilePipeRemoteInformation,               // 25
    FileMailslotQueryInformation,            // 26
    FileMailslotSetInformation,              // 27
    FileCompressionInformation,              // 28
    FileObjectIdInformation,                 // 29
    FileCompletionInformation,               // 30
    FileMoveClusterInformation,              // 31
    FileQuotaInformation,                    // 32
    FileReparsePointInformation,             // 33
    FileNetworkOpenInformation,              // 34
    FileAttributeTagInformation,             // 35
    FileTrackingInformation,                 // 36
    FileIdBothDirectoryInformation,          // 37
    FileIdFullDirectoryInformation,          // 38
    FileValidDataLengthInformation,          // 39
    FileShortNameInformation,                // 40
    FileIoCompletionNotificationInformation, // 41
    FileIoStatusBlockRangeInformation,       // 42
    FileIoPriorityHintInformation,           // 43
    FileSfioReserveInformation,              // 44
    FileSfioVolumeInformation,               // 45
    FileHardLinkInformation,                 // 46
    FileProcessIdsUsingFileInformation,      // 47
    FileNormalizedNameInformation,           // 48
    FileNetworkPhysicalNameInformation,      // 49

    // Windows 7+
    FileIdGlobalTxDirectoryInformation,      // 50
    FileIsRemoteDeviceInformation,           // 51
    FileAttributeCacheInformation,           // 52
    FileNumaNodeInformation,                 // 53
    FileStandardLinkInformation,             // 54
    FileRemoteProtocolInformation,           // 55

    // Windows 8+
    FileRenameInformationBypassAccessCheck,  // 56 (kernel-mode only)
    FileLinkInformationBypassAccessCheck,    // 57 (kernel-mode only)
    FileVolumeNameInformation,               // 58
    FileIdInformation,                       // 59
    FileIdExtdDirectoryInformation,          // 60

    // WinBlue+
    FileReplaceCompletionInformation,        // 61
    FileHardLinkFullIdInformation,           // 62

    // Windows 10 THRESHOLD+
    FileIdExtdBothDirectoryInformation,      // 63
    FileDispositionInformationEx,            // 64
    FileRenameInformationEx,                 // 65
    FileRenameInformationExBypassAccessCheck,// 66 (kernel-mode only)

    // Windows 10 REDSTONE+
    FileDesiredStorageClassInformation,      // 67
    FileStatInformation,                     // 68
    FileMemoryPartitionInformation,          // 69

    // Windows 10 April 2018 Update+
    FileStatLxInformation,                   // 70
    FileCaseSensitiveInformation,            // 71

    // Windows 10 Fall 2018 Update+
    FileLinkInformationEx,                          // 72
    FileLinkInformationExBypassAccessCheck,         // 73
    FileStorageReserveIdInformation,                // 74
    FileCaseSensitiveInformationForceAccessCheck,   // 75

    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;


typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;


typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;


typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;


typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;


typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

// Windows 10 THRESHOLD+
typedef struct _FILE_STANDARD_INFORMATION_EX {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
    BOOLEAN AlternateStream;
    BOOLEAN MetadataAttribute;
} FILE_STANDARD_INFORMATION_EX, *PFILE_STANDARD_INFORMATION_EX;

typedef struct _FILE_INTERNAL_INFORMATION {
    LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;


typedef struct _FILE_EA_INFORMATION {
    ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;


typedef struct _FILE_ACCESS_INFORMATION {
    ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;


typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;


typedef struct _FILE_RENAME_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

#define FILE_RENAME_REPLACE_IF_EXISTS              0x00000001
#define FILE_RENAME_POSIX_SEMANTICS                0x00000002

// Renamed from original FILE_RENAME_INFORMATION in RS1+
typedef struct _FILE_RENAME_INFORMATION_EX {
    ULONG Flags;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION_EX, *PFILE_RENAME_INFORMATION_EX;

typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;


typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;


typedef struct _FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;


typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;


typedef struct _FILE_MODE_INFORMATION {
    ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;


typedef struct _FILE_ALIGNMENT_INFORMATION {
    ULONG AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION;


typedef struct _FILE_ALL_INFORMATION {
    FILE_BASIC_INFORMATION BasicInformation;
    FILE_STANDARD_INFORMATION StandardInformation;
    FILE_INTERNAL_INFORMATION InternalInformation;
    FILE_EA_INFORMATION EaInformation;
    FILE_ACCESS_INFORMATION AccessInformation;
    FILE_POSITION_INFORMATION PositionInformation;
    FILE_MODE_INFORMATION ModeInformation;
    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
    FILE_NAME_INFORMATION NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;


typedef struct _FILE_ALLOCATION_INFORMATION {
    LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;


typedef struct _FILE_END_OF_FILE_INFORMATION {
    LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;


typedef struct _FILE_STREAM_INFORMATION {
    ULONG NextEntryOffset;
    ULONG StreamNameLength;
    LARGE_INTEGER StreamSize;
    LARGE_INTEGER StreamAllocationSize;
    WCHAR StreamName[1];
} FILE_STREAM_INFORMATION, *PFILE_STREAM_INFORMATION;

typedef struct _FILE_PIPE_INFORMATION {
     ULONG ReadMode;
     ULONG CompletionMode;
} FILE_PIPE_INFORMATION, *PFILE_PIPE_INFORMATION;


typedef struct _FILE_PIPE_LOCAL_INFORMATION {
     ULONG NamedPipeType;
     ULONG NamedPipeConfiguration;
     ULONG MaximumInstances;
     ULONG CurrentInstances;
     ULONG InboundQuota;
     ULONG ReadDataAvailable;
     ULONG OutboundQuota;
     ULONG WriteQuotaAvailable;
     ULONG NamedPipeState;
     ULONG NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION, *PFILE_PIPE_LOCAL_INFORMATION;


typedef struct _FILE_PIPE_REMOTE_INFORMATION {
     LARGE_INTEGER CollectDataTime;
     ULONG MaximumCollectionCount;
} FILE_PIPE_REMOTE_INFORMATION, *PFILE_PIPE_REMOTE_INFORMATION;


typedef struct _FILE_MAILSLOT_QUERY_INFORMATION {
    ULONG MaximumMessageSize;
    ULONG MailslotQuota;
    ULONG NextMessageSize;
    ULONG MessagesAvailable;
    LARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_QUERY_INFORMATION, *PFILE_MAILSLOT_QUERY_INFORMATION;


typedef struct _FILE_MAILSLOT_SET_INFORMATION {
    PLARGE_INTEGER ReadTimeout;
} FILE_MAILSLOT_SET_INFORMATION, *PFILE_MAILSLOT_SET_INFORMATION;


typedef struct _FILE_COMPRESSION_INFORMATION {
    LARGE_INTEGER CompressedFileSize;
    USHORT CompressionFormat;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved[3];
} FILE_COMPRESSION_INFORMATION, *PFILE_COMPRESSION_INFORMATION;


typedef struct _FILE_LINK_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

#define FILE_LINK_REPLACE_IF_EXISTS                     0x00000001      // If a file with the given name already exists, it should be replaced with the new link. Equivalent to the ReplaceIfExists field used with the FileLinkInformation information class.
#define FILE_LINK_POSIX_SEMANTICS                       0x00000002      // If FILE_LINK_REPLACE_IF_EXISTS is also specified, allow replacing a file even if there are existing handles to it. Existing handles to the replaced file continue to be valid for operations such as read and write. Any subsequent opens of the target name will open the new link, not the replaced file.
#define FILE_LINK_SUPPRESS_STORAGE_RESERVE_INHERITANCE  0x00000008      // When creating a link in a new directory, suppress any inheritance rules related to the storage reserve ID property of the file.
#define FILE_LINK_NO_INCREASE_AVAILABLE_SPACE           0x00000010      // If FILE_LINK_SUPPRESS_STORAGE_RESERVE_INHERITANCE is not also specified, when creating a link in a new directory, automatically resize affected storage reserve areas to prevent the user visible free space on the volume from increasing. Requires manage volume access.
#define FILE_LINK_NO_DECREASE_AVAILABLE_SPACE           0x00000020      // If FILE_LINK_SUPPRESS_STORAGE_RESERVE_INHERITANCE is not also specified, when creating a link in a new directory, automatically resize affected storage reserve areas to prevent the user visible free space on the volume from decreasing. Requires manage volume access.
#define FILE_LINK_PRESERVE_AVAILABLE_SPACE              0x00000030      // Equivalent to specifying both FILE_LINK_NO_INCREASE_AVAILABLE_SPACE and FILE_LINK_NO_DECREASE_AVAILABLE_SPACE.
#define FILE_LINK_IGNORE_READONLY_ATTRIBUTE             0x00000040

// Renamed from original FILE_LINK_INFORMATION in RS5+
typedef struct _FILE_LINK_INFORMATION_EX {
    ULONG Flags;              // FileLinkInformationEx
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_INFORMATION_EX, *PFILE_LINK_INFORMATION_EX;


typedef struct _FILE_OBJECTID_INFORMATION
{
    LONGLONG FileReference;
    UCHAR ObjectId[16];
    union {
        struct {
            UCHAR BirthVolumeId[16];
            UCHAR BirthObjectId[16];
            UCHAR DomainId[16];
        } ;
        UCHAR ExtendedInfo[48];
    };
} FILE_OBJECTID_INFORMATION, *PFILE_OBJECTID_INFORMATION;


typedef struct _FILE_COMPLETION_INFORMATION {
    HANDLE Port;
    PVOID Key;
} FILE_COMPLETION_INFORMATION, *PFILE_COMPLETION_INFORMATION;


typedef struct _FILE_MOVE_CLUSTER_INFORMATION {
    ULONG ClusterCount;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_MOVE_CLUSTER_INFORMATION, *PFILE_MOVE_CLUSTER_INFORMATION;


typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;


typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION {
    ULONG FileAttributes;
    ULONG ReparseTag;
} FILE_ATTRIBUTE_TAG_INFORMATION, *PFILE_ATTRIBUTE_TAG_INFORMATION;


typedef struct _FILE_TRACKING_INFORMATION {
    HANDLE DestinationFile;
    ULONG ObjectInformationLength;
    CHAR ObjectInformation[1];
} FILE_TRACKING_INFORMATION, *PFILE_TRACKING_INFORMATION;


typedef struct _FILE_REPARSE_POINT_INFORMATION {
    LONGLONG FileReference;
    ULONG Tag;
} FILE_REPARSE_POINT_INFORMATION, *PFILE_REPARSE_POINT_INFORMATION;


typedef struct _FILE_QUOTA_INFORMATION {
    ULONG NextEntryOffset;
    ULONG SidLength;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER QuotaUsed;
    LARGE_INTEGER QuotaThreshold;
    LARGE_INTEGER QuotaLimit;
    SID Sid;
} FILE_QUOTA_INFORMATION, *PFILE_QUOTA_INFORMATION;


typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;


typedef struct _FILE_ID_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;


typedef struct _FILE_VALID_DATA_LENGTH_INFORMATION {
    LARGE_INTEGER ValidDataLength;
} FILE_VALID_DATA_LENGTH_INFORMATION, *PFILE_VALID_DATA_LENGTH_INFORMATION;

//
// Don't queue an entry to an associated completion port if returning success
// synchronously.
//
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS    0x1

//
// Don't set the file handle event on IO completion.
//
#define FILE_SKIP_SET_EVENT_ON_HANDLE           0x2

//
// Don't set user supplied event on successful fast-path IO completion.
//
#define FILE_SKIP_SET_USER_EVENT_ON_FAST_IO     0x4

typedef  struct _FILE_IO_COMPLETION_NOTIFICATION_INFORMATION {
    ULONG Flags;
} FILE_IO_COMPLETION_NOTIFICATION_INFORMATION, *PFILE_IO_COMPLETION_NOTIFICATION_INFORMATION;


typedef  struct _FILE_PROCESS_IDS_USING_FILE_INFORMATION {
    ULONG NumberOfProcessIdsInList;
    ULONG_PTR ProcessIdList[1];
} FILE_PROCESS_IDS_USING_FILE_INFORMATION, *PFILE_PROCESS_IDS_USING_FILE_INFORMATION;


typedef struct _FILE_IOSTATUSBLOCK_RANGE_INFORMATION {
    PUCHAR       IoStatusBlockRange;
    ULONG        Length;
} FILE_IOSTATUSBLOCK_RANGE_INFORMATION, *PFILE_IOSTATUSBLOCK_RANGE_INFORMATION;


typedef enum _IO_PRIORITY_HINT {
    IoPriorityVeryLow = 0,    // Winfs promotion, defragging, content indexing and other background I/Os
    IoPriorityLow,            // Prefetching for applications.
    IoPriorityNormal,         // Normal I/Os
    IoPriorityHigh,           // Used by filesystems for checkpoint I/O
    IoPriorityCritical,       // Used by memory manager. Not available for applications.
    MaxIoPriorityTypes
} IO_PRIORITY_HINT;


typedef struct _FILE_IO_PRIORITY_HINT_INFORMATION {
    IO_PRIORITY_HINT   PriorityHint;
} FILE_IO_PRIORITY_HINT_INFORMATION, *PFILE_IO_PRIORITY_HINT_INFORMATION;


//
// Support to reserve bandwidth for a file handle.
//

typedef struct _FILE_SFIO_RESERVE_INFORMATION {
    ULONG RequestsPerPeriod;
    ULONG Period;
    BOOLEAN RetryFailures;
    BOOLEAN Discardable;
    ULONG RequestSize;
    ULONG NumOutstandingRequests;
} FILE_SFIO_RESERVE_INFORMATION, *PFILE_SFIO_RESERVE_INFORMATION;

//
// Support to query bandwidth properties of a volume.
//

typedef struct _FILE_SFIO_VOLUME_INFORMATION {
    ULONG MaximumRequestsPerPeriod;
    ULONG MinimumPeriod;
    ULONG MinimumTransferSize;
} FILE_SFIO_VOLUME_INFORMATION, *PFILE_SFIO_VOLUME_INFORMATION;


typedef struct _FILE_LINK_ENTRY_INFORMATION {
    ULONG NextEntryOffset;
    LONGLONG ParentFileId;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_ENTRY_INFORMATION, *PFILE_LINK_ENTRY_INFORMATION;


typedef struct _FILE_LINKS_INFORMATION
{
    ULONG BytesNeeded;
    ULONG EntriesReturned;
    FILE_LINK_ENTRY_INFORMATION Entry;
} FILE_LINKS_INFORMATION, *PFILE_LINKS_INFORMATION;

#ifndef WINAPI_FAMILY_PC_APP    // In newer SDKs only
typedef struct _FILE_ID_128
{
    BYTE Identifier[16];
} FILE_ID_128, *PFILE_ID_128;
#endif

typedef struct _FILE_LINK_ENTRY_FULL_ID_INFORMATION
{
    ULONG NextEntryOffset;
    FILE_ID_128 ParentFileId;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_LINK_ENTRY_FULL_ID_INFORMATION, *PFILE_LINK_ENTRY_FULL_ID_INFORMATION;

typedef struct _FILE_ID_GLOBAL_TX_DIR_INFORMATION
{
  ULONG          NextEntryOffset;
  ULONG          FileIndex;
  LARGE_INTEGER  CreationTime;
  LARGE_INTEGER  LastAccessTime;
  LARGE_INTEGER  LastWriteTime;
  LARGE_INTEGER  ChangeTime;
  LARGE_INTEGER  EndOfFile;
  LARGE_INTEGER  AllocationSize;
  ULONG          FileAttributes;
  ULONG          FileNameLength;
  LARGE_INTEGER  FileId;
  GUID           LockingTransactionId;
  ULONG          TxInfoFlags;
  WCHAR          FileName[1];
} FILE_ID_GLOBAL_TX_DIR_INFORMATION, *PFILE_ID_GLOBAL_TX_DIR_INFORMATION;


typedef struct _FILE_IS_REMOTE_DEVICE_INFORMATION
{
    BOOLEAN IsRemote;
} FILE_IS_REMOTE_DEVICE_INFORMATION, *PFILE_IS_REMOTE_DEVICE_INFORMATION;

typedef struct _FILE_NUMA_NODE_INFORMATION {
    USHORT NodeNumber;
} FILE_NUMA_NODE_INFORMATION, *PFILE_NUMA_NODE_INFORMATION;

typedef struct _FILE_STANDARD_LINK_INFORMATION
{
    ULONG NumberOfAccessibleLinks;
    ULONG TotalNumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_LINK_INFORMATION, *PFILE_STANDARD_LINK_INFORMATION;

typedef struct _FILE_VOLUME_NAME_INFORMATION
{
    ULONG DeviceNameLength;
    WCHAR DeviceName[1];
} FILE_VOLUME_NAME_INFORMATION, *PFILE_VOLUME_NAME_INFORMATION;

typedef struct _FILE_ID_INFORMATION
{
    ULONGLONG VolumeSerialNumber;
    FILE_ID_128 FileId;
} FILE_ID_INFORMATION, *PFILE_ID_INFORMATION;

typedef struct _FILE_ID_EXTD_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    ULONG ReparsePointTag;
    FILE_ID_128 FileId;
    WCHAR FileName[1];
} FILE_ID_EXTD_DIR_INFORMATION, *PFILE_ID_EXTD_DIR_INFORMATION;

typedef struct _FILE_ID_EXTD_BOTH_DIR_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    ULONG ReparsePointTag;
    FILE_ID_128 FileId;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_ID_EXTD_BOTH_DIR_INFORMATION, *PFILE_ID_EXTD_BOTH_DIR_INFORMATION;

#define FILE_DISPOSITION_DO_NOT_DELETE              0x00000000
#define FILE_DISPOSITION_DELETE                     0x00000001
#define FILE_DISPOSITION_POSIX_SEMANTICS            0x00000002
#define FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK  0x00000004
#define FILE_DISPOSITION_ON_CLOSE                   0x00000008

typedef struct _FILE_DISPOSITION_INFORMATION_EX
{
    ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, *PFILE_DISPOSITION_INFORMATION_EX;

#ifndef FILE_STORAGE_TIER_FLAG_SMR
typedef enum _FILE_STORAGE_TIER_CLASS {

    FileStorageTierClassUnspecified = 0,
    FileStorageTierClassCapacity,
    FileStorageTierClassPerformance,
    FileStorageTierClassMax

} FILE_STORAGE_TIER_CLASS, *PFILE_STORAGE_TIER_CLASS;

typedef struct _FILE_DESIRED_STORAGE_CLASS_INFORMATION
{
    FILE_STORAGE_TIER_CLASS Class;      // Class type of the tier
    ULONG Flags;                        // Flags

} FILE_DESIRED_STORAGE_CLASS_INFORMATION, *PFILE_DESIRED_STORAGE_CLASS_INFORMATION;
#endif

typedef struct _FILE_STAT_INFORMATION
{
    LARGE_INTEGER FileId;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
    ULONG ReparseTag;
    ULONG NumberOfLinks;
    ULONG EffectiveAccess;
} FILE_STAT_INFORMATION, *PFILE_STAT_INFORMATION;

typedef struct _FILE_MEMORY_PARTITION_INFORMATION
{
    ULONG_PTR OwnerPartitionHandle;
    union {
        struct {
            UCHAR NoCrossPartitionAccess;
            UCHAR Spare[3];
        } DUMMYSTRUCTNAME;

        ULONG AllFlags;
    } Flags;
} FILE_MEMORY_PARTITION_INFORMATION, *PFILE_MEMORY_PARTITION_INFORMATION;

typedef struct _FILE_STAT_LX_INFORMATION {
    LARGE_INTEGER FileId;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
    ULONG ReparseTag;
    ULONG NumberOfLinks;
    ACCESS_MASK EffectiveAccess;
    ULONG LxFlags;
    ULONG LxUid;
    ULONG LxGid;
    ULONG LxMode;
    ULONG LxDeviceIdMajor;
    ULONG LxDeviceIdMinor;
} FILE_STAT_LX_INFORMATION, *PFILE_STAT_LX_INFORMATION;

#define FILE_CS_FLAG_CASE_SENSITIVE_DIR     0x00000001

typedef struct _FILE_CASE_SENSITIVE_INFORMATION
{
    ULONG Flags;
} FILE_CASE_SENSITIVE_INFORMATION, *PFILE_CASE_SENSITIVE_INFORMATION;

typedef enum _FSINFOCLASS {
    FileFsVolumeInformation       = 1,
    FileFsLabelInformation,      // 2
    FileFsSizeInformation,       // 3
    FileFsDeviceInformation,     // 4
    FileFsAttributeInformation,  // 5
    FileFsControlInformation,    // 6
    FileFsFullSizeInformation,   // 7
    FileFsObjectIdInformation,   // 8
    FileFsDriverPathInformation, // 9
    FileFsVolumeFlagsInformation,// 10
    FileFsSectorSizeInformation, // 11
    FileFsDataCopyInformation,   // 12
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;


typedef struct _FILE_FS_VOLUME_INFORMATION {
    LARGE_INTEGER VolumeCreationTime;
    ULONG VolumeSerialNumber;
    ULONG VolumeLabelLength;
    BOOLEAN SupportsObjects;
    WCHAR VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;


typedef struct _FILE_FS_LABEL_INFORMATION {
    ULONG VolumeLabelLength;
    WCHAR VolumeLabel[1];
} FILE_FS_LABEL_INFORMATION, *PFILE_FS_LABEL_INFORMATION;


typedef struct _FILE_FS_SIZE_INFORMATION {
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER AvailableAllocationUnits;
    ULONG SectorsPerAllocationUnit;
    ULONG BytesPerSector;
} FILE_FS_SIZE_INFORMATION, *PFILE_FS_SIZE_INFORMATION;


typedef struct _FILE_FS_DEVICE_INFORMATION {
    DEVICE_TYPE DeviceType;
    ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;


typedef struct _FILE_FS_ATTRIBUTE_INFORMATION {
    ULONG FileSystemAttributes;
    LONG MaximumComponentNameLength;
    ULONG FileSystemNameLength;
    WCHAR FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;


typedef struct _FILE_FS_CONTROL_INFORMATION {
    LARGE_INTEGER FreeSpaceStartFiltering;
    LARGE_INTEGER FreeSpaceThreshold;
    LARGE_INTEGER FreeSpaceStopFiltering;
    LARGE_INTEGER DefaultQuotaThreshold;
    LARGE_INTEGER DefaultQuotaLimit;
    ULONG FileSystemControlFlags;
} FILE_FS_CONTROL_INFORMATION, *PFILE_FS_CONTROL_INFORMATION;


typedef struct _FILE_FS_FULL_SIZE_INFORMATION {
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER CallerAvailableAllocationUnits;
    LARGE_INTEGER ActualAvailableAllocationUnits;
    ULONG SectorsPerAllocationUnit;
    ULONG BytesPerSector;
} FILE_FS_FULL_SIZE_INFORMATION, *PFILE_FS_FULL_SIZE_INFORMATION;


typedef struct _FILE_FS_OBJECTID_INFORMATION {
    UCHAR ObjectId[16];
    UCHAR ExtendedInfo[48];
} FILE_FS_OBJECTID_INFORMATION, *PFILE_FS_OBJECTID_INFORMATION;


typedef struct _FILE_FS_DRIVER_PATH_INFORMATION {
    BOOLEAN DriverInPath;
    ULONG   DriverNameLength;
    WCHAR   DriverName[1];
} FILE_FS_DRIVER_PATH_INFORMATION, *PFILE_FS_DRIVER_PATH_INFORMATION;


typedef struct _FILE_FS_VOLUME_FLAGS_INFORMATION {
    ULONG Flags;
} FILE_FS_VOLUME_FLAGS_INFORMATION, *PFILE_FS_VOLUME_FLAGS_INFORMATION;

typedef struct _FILE_FS_SECTOR_SIZE_INFORMATION {
    ULONG LogicalBytesPerSector;
    ULONG PhysicalBytesPerSectorForAtomicity;
    ULONG PhysicalBytesPerSectorForPerformance;
    ULONG FileSystemEffectivePhysicalBytesPerSectorForAtomicity;
    ULONG Flags;
    ULONG ByteOffsetForSectorAlignment;
    ULONG ByteOffsetForPartitionAlignment;
} FILE_FS_SECTOR_SIZE_INFORMATION, *PFILE_FS_SECTOR_SIZE_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateFile(
    OUT PHANDLE FileHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN  PLARGE_INTEGER AllocationSize,
    IN  ULONG FileAttributes,
    IN  ULONG ShareAccess,
    IN  ULONG CreateDisposition,
    IN  ULONG CreateOptions,
    IN  PVOID EaBuffer,
    IN  ULONG EaLength);

NTSYSAPI
NTSTATUS
NTAPI
ZwCreateFile(
    OUT PHANDLE FileHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN  PLARGE_INTEGER AllocationSize,
    IN  ULONG FileAttributes,
    IN  ULONG ShareAccess,
    IN  ULONG CreateDisposition,
    IN  ULONG CreateOptions,
    IN  PVOID EaBuffer,
    IN  ULONG EaLength);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryAttributesFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PFILE_BASIC_INFORMATION FileInformation
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryAttributesFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PFILE_BASIC_INFORMATION FileInformation
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryDirectoryFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN BOOLEAN ReturnSingleEntry,
    IN PUNICODE_STRING FileName OPTIONAL,
    IN BOOLEAN RestartScan
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN BOOLEAN ReturnSingleEntry,
    IN PUNICODE_STRING FileName OPTIONAL,
    IN BOOLEAN RestartScan
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryVolumeInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FsInformation,
    IN ULONG Length,
    IN FS_INFORMATION_CLASS FsInformationClass
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryVolumeInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FsInformation,
    IN ULONG Length,
    IN FS_INFORMATION_CLASS FsInformationClass
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetVolumeInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FsInformation,
    IN ULONG Length,
    IN FS_INFORMATION_CLASS FsInformationClass
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwSetVolumeInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FsInformation,
    IN ULONG Length,
    IN FS_INFORMATION_CLASS FsInformationClass
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryEaFile(
    IN  HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN  ULONG Length,
    IN  BOOLEAN ReturnSingleEntry,
    IN  PVOID EaList OPTIONAL,
    IN  ULONG EaListLength,
    IN  PULONG EaIndex OPTIONAL,
    IN  BOOLEAN RestartScan
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryEaFile(
    IN  HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN  ULONG Length,
    IN  BOOLEAN ReturnSingleEntry,
    IN  PVOID EaList OPTIONAL,
    IN  ULONG EaListLength,
    IN  PULONG EaIndex OPTIONAL,
    IN  BOOLEAN RestartScan
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetEaFile(
    IN  HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN  PVOID Buffer,
    IN  ULONG Length
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwSetEaFile(
    IN  HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN  PVOID Buffer,
    IN  ULONG Length
    );

NTSYSAPI
NTSTATUS
NTAPI
NtReadFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtReadFileScatter(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PFILE_SEGMENT_ELEMENT SegmentArray,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwReadFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtWriteFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwWriteFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtDeleteFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwDeleteFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
NtFlushBuffersFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwFlushBuffersFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock
    );

NTSYSAPI
NTSTATUS
NTAPI
NtDeviceIoControlFile(
    IN  HANDLE FileHandle,
    IN  HANDLE Event,
    IN  PIO_APC_ROUTINE ApcRoutine,
    IN  PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN  ULONG IoControlCode,
    IN  PVOID InputBuffer,
    IN  ULONG InputBufferLength,
    IN  PVOID OutputBuffer,
    IN  ULONG OutputBufferLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwDeviceIoControlFile(
    IN  HANDLE FileHandle,
    IN  HANDLE Event,
    IN  PIO_APC_ROUTINE ApcRoutine,
    IN  PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN  ULONG IoControlCode,
    IN  PVOID InputBuffer,
    IN  ULONG InputBufferLength,
    IN  PVOID OutputBuffer,
    IN  ULONG OutputBufferLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtFsControlFile(
    IN  HANDLE FileHandle,
    IN  HANDLE Event,
    IN  PIO_APC_ROUTINE ApcRoutine,
    IN  PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN  ULONG FsControlCode,
    IN  PVOID InputBuffer,
    IN  ULONG InputBufferLength,
    IN  PVOID OutputBuffer,
    IN  ULONG OutputBufferLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwFsControlFile(
    IN  HANDLE FileHandle,
    IN  HANDLE Event,
    IN  PIO_APC_ROUTINE ApcRoutine,
    IN  PVOID ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN  ULONG FsControlCode,
    IN  PVOID InputBuffer,
    IN  ULONG InputBufferLength,
    IN  PVOID OutputBuffer,
    IN  ULONG OutputBufferLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtCancelIoFile(
    IN HANDLE Filehandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwCancelIoFile(
    IN HANDLE Filehandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock
    );

NTSYSAPI
NTSTATUS
NTAPI
NtLockFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER ByteOffset,
    IN PLARGE_INTEGER Length,
    IN ULONG Key,
    IN BOOLEAN FailImmediately,
    IN BOOLEAN ExclusiveLock
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwLockFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER ByteOffset,
    IN PLARGE_INTEGER Length,
    IN ULONG Key,
    IN BOOLEAN FailImmediately,
    IN BOOLEAN ExclusiveLock
    );

NTSYSAPI
NTSTATUS
NTAPI
NtUnlockFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER ByteOffset,
    IN PLARGE_INTEGER Length,
    IN ULONG Key
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwUnlockFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER ByteOffset,
    IN PLARGE_INTEGER Length,
    IN ULONG Key
    );


//-----------------------------------------------------------------------------
// DOS <-> NT path functions

// OUT Disposition values for RtlNtPathNameToDosPathName
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_AMBIGUOUS   (0x00000001)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_UNC         (0x00000002)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_DRIVE       (0x00000003)
#define RTL_NT_PATH_NAME_TO_DOS_PATH_NAME_ALREADY_DOS (0x00000004)

typedef enum _RTL_PATH_TYPE
{
    RtlPathTypeUnknown,         // 0
    RtlPathTypeUncAbsolute,     // 1
    RtlPathTypeDriveAbsolute,   // 2
    RtlPathTypeDriveRelative,   // 3
    RtlPathTypeRooted,          // 4
    RtlPathTypeRelative,        // 5
    RtlPathTypeLocalDevice,     // 6
    RtlPathTypeRootLocalDevice  // 7
} RTL_PATH_TYPE, *PRTL_PATH_TYPE;

// CURDIR structure
typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

NTSYSAPI
ULONG
NTAPI
RtlIsDosDeviceName_U(
    IN PWSTR DosFileName
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlDosPathNameToNtPathName_U (
    IN  PCWSTR DosPathName,
    OUT PUNICODE_STRING NtPathName,
    OUT PWSTR * NtFileNamePart OPTIONAL,
    OUT PCURDIR DirectoryInfo OPTIONAL
    );

NTSYSAPI
ULONG
NTAPI
RtlGetFullPathName_U(
    PCWSTR lpFileName,
    ULONG nBufferLength,
    PWSTR lpBuffer,
    PWSTR *lpFilePart OPTIONAL
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlDoesFileExists_U(
    IN PCWSTR FileName
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlNtPathNameToDosPathName(                     // Available in Windows XP or newer
    IN  ULONG Flags,
    IN OUT PRTL_UNICODE_STRING_BUFFER Path,
    OUT PULONG Disposition OPTIONAL,
    IN OUT PWSTR * FilePart OPTIONAL
    );

//-----------------------------------------------------------------------------
// Process functions

#define GDI_HANDLE_BUFFER_SIZE      60

// RTL_USER_PROCESS_PARAMETERS::Flags
#define RTL_USER_PROC_PARAMS_NORMALIZED         0x00000001
#define RTL_USER_PROC_PROFILE_USER              0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL            0x00000004
#define RTL_USER_PROC_PROFILE_SERVER            0x00000008
#define RTL_USER_PROC_RESERVE_1MB               0x00000020
#define RTL_USER_PROC_RESERVE_16MB              0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE            0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT     0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL     0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT      0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING         0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS             0x00020000
#define RTL_USER_PROC_SECURE_PROCESS            0x80000000

// PEB::NtGlobalFlag
#define FLG_STOP_ON_EXCEPTION                   0x00000001          // (soe) Stop on exception
#define FLG_SHOW_LDR_SNAPS                      0x00000002          // (sls) Show loader snaps
#define FLG_DEBUG_INITIAL_COMMAND               0x00000004          // (dic) Debug initial command
#define FLG_STOP_ON_HUNG_GUI                    0x00000008          // (shg) Stop on hung GUI
#define FLG_HEAP_ENABLE_TAIL_CHECK              0x00000010          // (htc) Enable heap tail checking
#define FLG_HEAP_ENABLE_FREE_CHECK              0x00000020          // (hfc) Enable heap free checking
#define FLG_HEAP_VALIDATE_PARAMETERS            0x00000040          // (hpc) Enable heap parameter checking
#define FLG_HEAP_VALIDATE_ALL                   0x00000080          // (hvc) Enable heap validation on call
#define FLG_POOL_ENABLE_TAIL_CHECK              0x00000100          // (vrf) Enable application verifier
#define FLG_MONITOR_SILENT_PROCESS_EXIT         0x00000200          // (   ) Enable silent process exit monitoring
#define FLG_POOL_ENABLE_TAGGING                 0x00000400          // (ptg) Enable pool tagging (Windows 2000 and Windows XP only)
#define FLG_HEAP_ENABLE_TAGGING                 0x00000800          // (htg) Enable heap tagging
#define FLG_USER_STACK_TRACE_DB                 0x00001000          // (ust) Create user mode stack trace database
#define FLG_KERNEL_STACK_TRACE_DB               0x00002000          // (kst) Create kernel mode stack trace database
#define FLG_MAINTAIN_OBJECT_TYPELIST            0x00004000          // (otl) Maintain a list of objects for each type
#define FLG_HEAP_ENABLE_TAG_BY_DLL              0x00008000          // (htd) Enable heap tagging by DLL
#define FLG_DISABLE_STACK_EXTENSION             0x00010000          // (dse) Disable stack extension
#define FLG_ENABLE_CSRDEBUG                     0x00020000          // (d32) Enable debugging of Win32 subsystem
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD           0x00040000          // (ksl) Enable loading of kernel debugger symbols
#define FLG_DISABLE_PAGE_KERNEL_STACKS          0x00080000          // (dps) Disable paging of kernel stacks
#define FLG_ENABLE_SYSTEM_CRIT_BREAKS           0x00100000          // (scb) Enable system critical breaks
#define FLG_HEAP_DISABLE_COALESCING             0x00200000          // (dhc) Disable heap coalesce on free
#define FLG_ENABLE_CLOSE_EXCEPTIONS             0x00400000          // (ece) Enable close exception
#define FLG_ENABLE_EXCEPTION_LOGGING            0x00800000          // (eel) Enable exception logging
#define FLG_ENABLE_HANDLE_TYPE_TAGGING          0x01000000          // (eot) Enable object handle type tagging
#define FLG_HEAP_PAGE_ALLOCS                    0x02000000          // (hpa) Enable page heap
#define FLG_DEBUG_INITIAL_COMMAND_EX            0x04000000          // (dwl) Debug WinLogon
#define FLG_DISABLE_DBGPRINT                    0x08000000          // (ddp) Buffer DbgPrint Output
#define FLG_CRITSEC_EVENT_CREATION              0x10000000          // (cse) Early critical section event creation
#define FLG_STOP_ON_UNHANDLED_EXCEPTION         0x20000000          // (sue) Stop on unhandled user-mode exception
#define FLG_ENABLE_HANDLE_EXCEPTIONS            0x40000000          // (bhd) Enable bad handles detection
#define FLG_DISABLE_PROTDLLS                    0x80000000          // (dpd) Disable protected DLL verification
#define FLG_VALID_BITS                          0xFFFFFFFF

// For ProcessExecuteFlags
#define MEM_EXECUTE_OPTION_DISABLE                          0x1
#define MEM_EXECUTE_OPTION_ENABLE                           0x2
#define MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION          0x4
#define MEM_EXECUTE_OPTION_PERMANENT                        0x8
#define MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE          0x10
#define MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE            0x20
#define MEM_EXECUTE_OPTION_DISABLE_EXCEPTION_CHAIN_VALIDATION	0x40
#define MEM_EXECUTE_OPTION_VALID_FLAGS                      0x3F

//
// Process Information Classes
//

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,                // 0x00
    ProcessQuotaLimits,                     // 0x01
    ProcessIoCounters,                      // 0x02
    ProcessVmCounters,                      // 0x03
    ProcessTimes,                           // 0x04
    ProcessBasePriority,                    // 0x05
    ProcessRaisePriority,                   // 0x06
    ProcessDebugPort,                       // 0x07
    ProcessExceptionPort,                   // 0x08
    ProcessAccessToken,                     // 0x09
    ProcessLdtInformation,                  // 0x0A
    ProcessLdtSize,                         // 0x0B
    ProcessDefaultHardErrorMode,            // 0x0C
    ProcessIoPortHandlers,                  // 0x0D Note: this is kernel mode only
    ProcessPooledUsageAndLimits,            // 0x0E
    ProcessWorkingSetWatch,                 // 0x0F
    ProcessUserModeIOPL,                    // 0x10
    ProcessEnableAlignmentFaultFixup,       // 0x11
    ProcessPriorityClass,                   // 0x12
    ProcessWx86Information,                 // 0x13
    ProcessHandleCount,                     // 0x14
    ProcessAffinityMask,                    // 0x15
    ProcessPriorityBoost,                   // 0x16
    ProcessDeviceMap,                       // 0x17
    ProcessSessionInformation,              // 0x18
    ProcessForegroundInformation,           // 0x19
    ProcessWow64Information,                // 0x1A
    ProcessImageFileName,                   // 0x1B
    ProcessLUIDDeviceMapsEnabled,           // 0x1C
    ProcessBreakOnTermination,              // 0x1D
    ProcessDebugObjectHandle,               // 0x1E
    ProcessDebugFlags,                      // 0x1F
    ProcessHandleTracing,                   // 0x20
    ProcessIoPriority,                      // 0x21
    ProcessExecuteFlags,                    // 0x22
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    MaxProcessInfoClass                     // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

//
// Thread Information Classes
//

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,                 // 0x00
    ThreadTimes,                            // 0x01
    ThreadPriority,                         // 0x02
    ThreadBasePriority,                     // 0x03
    ThreadAffinityMask,                     // 0x04
    ThreadImpersonationToken,               // 0x05  HANDLE
    ThreadDescriptorTableEntry,             // 0x06  ULONG Selector + LDT_ENTRY
    ThreadEnableAlignmentFaultFixup,        // 0x07
    ThreadEventPair,                        // 0x08
    ThreadQuerySetWin32StartAddress,        // 0x09
    ThreadZeroTlsCell,                      // 0x0A
    ThreadPerformanceCount,                 // 0x0B
    ThreadAmILastThread,                    // 0x0C  ULONG
    ThreadIdealProcessor,                   // 0x0D
    ThreadPriorityBoost,                    // 0x0E
    ThreadSetTlsArrayAddress,               // 0x0F
    ThreadIsIoPending,                      // 0x10
    ThreadHideFromDebugger,                 // 0x11
    MaxThreadInfoClass
} THREADINFOCLASS;


typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG  TimeStamp;
    STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;


typedef struct _SECTION_IMAGE_INFORMATION
{
    PVOID TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    union {
        struct {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    ULONG GpValue;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    BOOLEAN Spare1;
    ULONG LoaderFlags;
    ULONG ImageFileSize;                    // Reserved[0] for NT 4.0 and 2000
    ULONG CheckSum;                         // Reserved[1] until Vista
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;


typedef struct _RTL_USER_PROCESS_INFORMATION
{
    ULONG Length;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;

} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;                            // Should be set before call RtlCreateProcessParameters
    ULONG Length;                                   // Length of valid structure
    ULONG Flags;                                    // Currently only PPF_NORMALIZED (1) is known:
                                                    //  - Means that structure is normalized by call RtlNormalizeProcessParameters
    ULONG DebugFlags;

    PVOID ConsoleHandle;                            // HWND to console window associated with process (if any).
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;                        // Specified in DOS-like symbolic link path, ex: "C:/WinNT/SYSTEM32"
    UNICODE_STRING DllPath;                         // DOS-like paths separated by ';' where system should search for DLL files.
    UNICODE_STRING ImagePathName;                   // Full path in DOS-like format to process'es file image.
    UNICODE_STRING CommandLine;                     // Command line
    PVOID Environment;                              // Pointer to environment block (see RtlCreateEnvironment)
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;                            // Fill attribute for console window
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;                     // Name of WindowStation and Desktop objects, where process is assigned
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[0x20];

    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

//
// Process Environment Block
//

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK *Next;
    ULONG Size;

} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;


typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;               // Points to the loaded modules (main EXE usually)
    LIST_ENTRY InMemoryOrderModuleList;             // Points to all modules (EXE and all DLLs)
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;
    BOOLEAN    ShutdownInProgress;                  // Windows 10
    HANDLE     ShutdownThreadId;                    // Windows 10

} PEB_LDR_DATA, *PPEB_LDR_DATA;

#define LDRP_PACKED_BINARY              0x00000001
#define LDRP_STATIC_LINK                0x00000002
#define LDRP_IMAGE_DLL                  0x00000004
#define LDRP_LOAD_NOTIFICATION_SENT     0x00000008
#define LDRP_TELEMETRY_ENTRY_PROCESSED  0x00000010
#define LDRP_PROCESS_STATIC_IMPORT      0x00000020
#define LDRP_IN_LEGACY_LISTS            0x00000040
#define LDRP_IN_INDEXES                 0x00000080
#define LDRP_SHIM_DLL                   0x00000100
#define LDRP_IN_EXCEPTION_TABLE         0x00000200
#define LDRP_LOAD_IN_PROGRESS           0x00001000
#define LDRP_LOAD_CONFIG_PROCESSED      0x00002000    // Was: LDRP_UNLOAD_IN_PROGRESS
#define LDRP_ENTRY_PROCESSED            0x00004000
#define LDRP_ENTRY_PROTECT_DELAY_LOAD   0x00008000    // Was: LDRP_ENTRY_INSERTED
#define LDRP_CURRENT_LOAD               0x00010000
#define LDRP_FAILED_BUILTIN_LOAD        0x00020000
#define LDRP_DONT_CALL_FOR_THREADS      0x00040000
#define LDRP_PROCESS_ATTACH_CALLED      0x00080000
#define LDRP_DEBUG_SYMBOLS_LOADED       0x00100000
#define LDRP_IMAGE_NOT_AT_BASE          0x00200000
#define LDRP_COR_IMAGE                  0x00400000
#define LDRP_COR_OWNS_UNMAP             0x00800000
#define LDRP_SYSTEM_MAPPED              0x01000000
#define LDRP_IMAGE_VERIFYING            0x02000000
#define LDRP_DRIVER_DEPENDENT_DLL       0x04000000
#define LDRP_ENTRY_NATIVE               0x08000000
#define LDRP_REDIRECTED                 0x10000000
#define LDRP_NON_PAGED_DEBUG_INFO       0x20000000
#define LDRP_MM_LOADED                  0x40000000
#define LDRP_COMPAT_DATABASE_PROCESSED  0x80000000

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;                             // Base address of the module
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG  Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
    PVOID ContextInformation;
    PVOID OriginalBase;
    LARGE_INTEGER LoadTime;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#ifdef _MSC_VER
#pragma warning(disable: 4214)      // warning C4214: nonstandard extension used : bit field types other than int
#endif

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        UCHAR BitField;
        struct
        {
            UCHAR ImageUsesLargePages:1;
            UCHAR IsProtectedProcess:1;
            UCHAR IsImageDynamicallyRelocated:1;
            UCHAR SkipPatchingUser32Forwarders:1;
            UCHAR IsPackagedProcess:1;
            UCHAR IsAppContainer:1;
            UCHAR IsProtectedProcessLight:1;
            UCHAR SpareBits:1;
        };
    };

    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;

    //--- Windows 7. Can be different in different Windows version. ---------------

    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;

    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ReservedBits0 : 25;
        };
    };

    union
    {
    PVOID KernelCallbackTable;
    PVOID UserSharedInfoPtr;
    };

    ULONG SystemReserved[1];
    PVOID AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];                         // relates to TLS_MINIMUM_AVAILABLE
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID *ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    //
    // Useful information for LdrpInitialize

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    //
    // Passed up from MmCreatePeb from Session Manager registry key
    //

    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;

    //
    // Where heap manager keeps track of all heaps created for a process
    // Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
    // to point to the first free byte after the PEB and MaximumNumberOfHeaps
    // is computed from the page size used to hold the PEB, less the fixed
    // size of this data structure.
    //

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps;

    //
    //
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PRTL_CRITICAL_SECTION LoaderLock;

    //
    // Following fields filled in by MmCreatePeb from system values and/or
    // image header. These fields have changed since Windows NT 4.0,
    // so use with caution
    //

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];
    PVOID PostProcessInitRoutine;

    // More here. Do not use.

} PEB, *PPEB;


//
// Thread environment block
//

typedef struct _TEB
{
    NT_TIB NtTib;
    PVOID  EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;

    // Incomplete

} TEB, *PTEB;


typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;

} PROCESS_BASIC_INFORMATION,*PPROCESS_BASIC_INFORMATION;

typedef BOOLEAN (*PDLL_INIT_ROUTINE)(
    IN PVOID DllHandle,
    IN ULONG Reason,
    IN PCONTEXT Context OPTIONAL
    );

typedef VOID (NTAPI *PUSER_THREAD_START_ROUTINE)(
    IN PVOID ApcArgument1
    );

typedef VOID (*PPS_APC_ROUTINE) (
    __in_opt PVOID ApcArgument1,
    __in_opt PVOID ApcArgument2,
    __in_opt PVOID ApcArgument3
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserThread(
    IN HANDLE Process,
    IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG_PTR ZeroBits OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN SIZE_T CommittedStackSize OPTIONAL,
    IN PUSER_THREAD_START_ROUTINE StartAddress,
    IN PVOID Parameter OPTIONAL,
    OUT PHANDLE Thread OPTIONAL,
    OUT PCLIENT_ID ClientId OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenThread (
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenThread (
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationThread(
    IN HANDLE          ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID           ThreadInformation,
    IN ULONG           ThreadInformationLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationThread(
    IN HANDLE          ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID           ThreadInformation,
    IN ULONG           ThreadInformationLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSuspendThread(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtResumeThread(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtTerminateThread(
    HANDLE Thread,
    NTSTATUS ExitStatus
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwTerminateThread(
    HANDLE Thread,
    NTSTATUS ExitStatus
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetThreadExecutionState(
    ULONG EsFlags,
    PULONG PreviousFlags
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueueApcThread(
    HANDLE ThreadHandle,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueueApcThread(
    HANDLE ThreadHandle,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlAdjustPrivilege(
    ULONG    Privilege,
    BOOLEAN  Enable,
    BOOLEAN  CurrentThread,
    PBOOLEAN Enabled
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParameters(
    PRTL_USER_PROCESS_PARAMETERS *ProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData
    );

NTSYSAPI
PRTL_USER_PROCESS_PARAMETERS
NTAPI
RtlNormalizeProcessParams(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyProcessParameters(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateUserProcess(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
    );

#define NtCurrentProcess() ((HANDLE) -1)
#define NtCurrentThread()  ((HANDLE) -2)
#define NtCurrentPeb()     ((PPEB)(NtCurrentTeb()->ProcessEnvironmentBlock))

NTSYSAPI
NTSTATUS
NTAPI
NtCreateProcess(
    OUT PHANDLE ProcessHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN  HANDLE ParentProcess,
    IN  BOOLEAN InheritObjectTable,
    IN  HANDLE SectionHandle OPTIONAL,
    IN  HANDLE DebugPort OPTIONAL,
    IN  HANDLE ExceptionPort OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwCreateProcess(
    OUT PHANDLE ProcessHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN  HANDLE ParentProcess,
    IN  BOOLEAN InheritObjectTable,
    IN  HANDLE SectionHandle OPTIONAL,
    IN  HANDLE DebugPort OPTIONAL,
    IN  HANDLE ExceptionPort OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenProcess (
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenProcess (
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationProcess (
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtTerminateProcess(
    HANDLE Process,
    NTSTATUS ExitStatus
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwTerminateProcess(
    HANDLE Process,
    NTSTATUS ExitStatus
    );

//------------------------------------------------------------------------------
// LPC Functions

#define MAX_LPC_DATA 0x130    // Maximum number of bytes that can be copied through LPC

// Valid values for PORT_MESSAGE::u2::s2::Type
#define LPC_REQUEST                  1
#define LPC_REPLY                    2
#define LPC_DATAGRAM                 3
#define LPC_LOST_REPLY               4
#define LPC_PORT_CLOSED              5
#define LPC_CLIENT_DIED              6
#define LPC_EXCEPTION                7
#define LPC_DEBUG_EVENT              8
#define LPC_ERROR_EVENT              9
#define LPC_CONNECTION_REQUEST      10

#define ALPC_REQUEST            0x2000 | LPC_REQUEST
#define ALPC_CONNECTION_REQUEST 0x2000 | LPC_CONNECTION_REQUEST

#define LPC_MESSAGE_BASE_SIZE	24

//
// Define header for Port Message
//

typedef struct _PORT_MESSAGE
{
    union
    {
        struct
        {
            USHORT DataLength;          // Length of data following the header (bytes)
            USHORT TotalLength;         // Length of data + sizeof(PORT_MESSAGE)
        } s1;
        ULONG Length;
    } u1;

    union
    {
        struct
        {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;

    union
    {
        CLIENT_ID ClientId;
        double   DoNotUseThisField;     // Force quadword alignment
    };

    ULONG  MessageId;                   // Identifier of the particular message instance

    union
    {
        ULONG_PTR ClientViewSize;       // Size of section created by the sender (in bytes)
        ULONG  CallbackId;              //
    };

} PORT_MESSAGE, *PPORT_MESSAGE, LPC_MESSAGE, *PLPC_MESSAGE;

//
// Define structure for initializing shared memory on the caller's side of the port
//

typedef struct _PORT_VIEW {

    ULONG  Length;                      // Size of this structure
    HANDLE SectionHandle;               // Handle to section object with
                                        // SECTION_MAP_WRITE and SECTION_MAP_READ
    ULONG  SectionOffset;               // The offset in the section to map a view for
                                        // the port data area. The offset must be aligned
                                        // with the allocation granularity of the system.
    SIZE_T ViewSize;                    // The size of the view (in bytes)
    PVOID  ViewBase;                    // The base address of the view in the creator
                                        //
    PVOID  ViewRemoteBase;              // The base address of the view in the process
                                        // connected to the port.
} PORT_VIEW, *PPORT_VIEW;

//
// Define structure for shared memory coming from remote side of the port
//

typedef struct _REMOTE_PORT_VIEW {

    ULONG  Length;                      // Size of this structure
    SIZE_T ViewSize;                    // The size of the view (bytes)
    PVOID  ViewBase;                    // Base address of the view

} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

//
// Macro for initializing the message header
//

#ifndef InitializeMessageHeader
#define InitializeMessageHeader(ph, l, t)                              \
{                                                                      \
    (ph)->u1.s1.TotalLength      = (USHORT)(l);                        \
    (ph)->u1.s1.DataLength       = (USHORT)(l - sizeof(PORT_MESSAGE)); \
    (ph)->u2.s2.Type             = (USHORT)(t);                        \
    (ph)->u2.s2.DataInfoOffset   = 0;                                  \
    (ph)->ClientId.UniqueProcess = NULL;                               \
    (ph)->ClientId.UniqueThread  = NULL;                               \
    (ph)->MessageId              = 0;                                  \
    (ph)->ClientViewSize         = 0;                                  \
}
#endif

/*++

    NtCreatePort
    ============

    Creates a LPC port object. The creator of the LPC port becomes a server
    of LPC communication

    PortHandle - Points to a variable that will receive the
        port object handle if the call is successful.

    ObjectAttributes - Points to a structure that specifies the object�s
        attributes. OBJ_KERNEL_HANDLE, OBJ_OPENLINK, OBJ_OPENIF, OBJ_EXCLUSIVE,
        OBJ_PERMANENT, and OBJ_INHERIT are not valid attributes for a port object.

    MaxConnectionInfoLength - The maximum size, in bytes, of data that can
        be sent through the port.

    MaxMessageLength - The maximum size, in bytes, of a message
        that can be sent through the port.

    MaxPoolUsage - Specifies the maximum amount of NonPaged pool that can be used for
        message storage. Zero means default value.

    ZwCreatePort verifies that (MaxDataSize <= 0x104) and (MaxMessageSize <= 0x148).

--*/

NTSYSAPI
NTSTATUS
NTAPI
NtCreatePort(
    OUT PHANDLE PortHandle,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  ULONG MaxConnectionInfoLength,
    IN  ULONG MaxMessageLength,
    IN  ULONG MaxPoolUsage
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwCreatePort(
    OUT PHANDLE PortHandle,
    IN  POBJECT_ATTRIBUTES ObjectAttributes,
    IN  ULONG MaxConnectionInfoLength,
    IN  ULONG MaxMessageLength,
    IN  ULONG MaxPoolUsage
    );


/*++

    NtConnectPort
    =============

    Creates a port connected to a named port (cliend side).

    PortHandle - A pointer to a variable that will receive the client
        communication port object handle value.

    PortName - Points to a structure that specifies the name
        of the port to connect to.

    SecurityQos - Points to a structure that specifies the level
        of impersonation available to the port listener.

    ClientView - Optionally points to a structure describing
        the shared memory region used to send large amounts of data
        to the listener; if the call is successful, this will be updated.

    ServerView - Optionally points to a caller-allocated buffer
        or variable that receives information on the shared memory region
        used by the listener to send large amounts of data to the
        caller.

    MaxMessageLength - Optionally points to a variable that receives the size,
        in bytes, of the largest message that can be sent through the port.

    ConnectionInformation - Optionally points to a caller-allocated
        buffer or variable that specifies connect data to send to the listener,
        and receives connect data sent by the listener.

    ConnectionInformationLength - Optionally points to a variable that
        specifies the size, in bytes, of the connect data to send
        to the listener, and receives the size of the connect data
        sent by the listener.

--*/

NTSYSAPI
NTSTATUS
NTAPI
NtConnectPort(
    OUT PHANDLE PortHandle,
    IN  PUNICODE_STRING PortName,
    IN  PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN  OUT PPORT_VIEW ClientView OPTIONAL,
    OUT PREMOTE_PORT_VIEW ServerView OPTIONAL,
    OUT PULONG MaxMessageLength OPTIONAL,
    IN  OUT PVOID ConnectionInformation OPTIONAL,
    IN  OUT PULONG ConnectionInformationLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwConnectPort(
    OUT PHANDLE PortHandle,
    IN  PUNICODE_STRING PortName,
    IN  PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN  OUT PPORT_VIEW ClientView OPTIONAL,
    OUT PREMOTE_PORT_VIEW ServerView OPTIONAL,
    OUT PULONG MaxMessageLength OPTIONAL,
    IN  OUT PVOID ConnectionInformation OPTIONAL,
    IN  OUT PULONG ConnectionInformationLength OPTIONAL
    );


/*++

    NtListenPort
    ============

    Listens on a port for a connection request message on the server side.

    PortHandle - A handle to a port object. The handle doesn't need
        to grant any specific access.

    ConnectionRequest - Points to a caller-allocated buffer
        or variable that receives the connect message sent to
        the port.

--*/

NTSYSAPI
NTSTATUS
NTAPI
NtListenPort(
    IN  HANDLE PortHandle,
    OUT PPORT_MESSAGE RequestMessage
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwListenPort(
    IN  HANDLE PortHandle,
    OUT PPORT_MESSAGE RequestMessage
    );

/*++

    NtAcceptConnectPort
    ===================

    Accepts or rejects a connection request on the server side.

    PortHandle - Points to a variable that will receive the port object
        handle if the call is successful.

    PortContext - A numeric identifier to be associated with the port.

    ConnectionRequest - Points to a caller-allocated buffer or variable
        that identifies the connection request and contains any connect
        data that should be returned to requestor of the connection

    AcceptConnection - Specifies whether the connection should
        be accepted or not

    ServerView - Optionally points to a structure describing
        the shared memory region used to send large amounts of data to the
        requestor; if the call is successful, this will be updated

    ClientView - Optionally points to a caller-allocated buffer
        or variable that receives information on the shared memory
        region used by the requestor to send large amounts of data to the
        caller

--*/


NTSYSAPI
NTSTATUS
NTAPI
NtAcceptConnectPort(
    OUT PHANDLE PortHandle,
    IN  PVOID PortContext OPTIONAL,
    IN  PPORT_MESSAGE ConnectionRequest,
    IN  BOOLEAN AcceptConnection,
    IN  OUT PPORT_VIEW ServerView OPTIONAL,
    OUT PREMOTE_PORT_VIEW ClientView OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwAcceptConnectPort(
    OUT PHANDLE PortHandle,
    IN  PVOID PortContext OPTIONAL,
    IN  PPORT_MESSAGE ConnectionRequest,
    IN  BOOLEAN AcceptConnection,
    IN  OUT PPORT_VIEW ServerView OPTIONAL,
    OUT PREMOTE_PORT_VIEW ClientView OPTIONAL
    );


/*++

    NtCompleteConnectPort
    =====================

    Completes the port connection process on the server side.

    PortHandle - A handle to a port object. The handle doesn't need
        to grant any specific access.

--*/

NTSYSAPI
NTSTATUS
NTAPI
NtCompleteConnectPort(
    IN  HANDLE PortHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwCompleteConnectPort(
    IN  HANDLE PortHandle
    );


/*++

    NtRequestPort
    =============

    Sends a request message to a port (client side)

    PortHandle - A handle to a port object. The handle doesn't need
        to grant any specific access.

    RequestMessage - Points to a caller-allocated buffer or variable
        that specifies the request message to send to the port.

--*/

NTSYSAPI
NTSTATUS
NTAPI
NtRequestPort (
    IN  HANDLE PortHandle,
    IN  PPORT_MESSAGE RequestMessage
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwRequestPort (
    IN  HANDLE PortHandle,
    IN  PPORT_MESSAGE RequestMessage
    );

/*++

    NtRequestWaitReplyPort
    ======================

    Sends a request message to a port and waits for a reply (client side)

    PortHandle - A handle to a port object. The handle doesn't need
        to grant any specific access.

    RequestMessage - Points to a caller-allocated buffer or variable
        that specifies the request message to send to the port.

    ReplyMessage - Points to a caller-allocated buffer or variable
        that receives the reply message sent to the port.

--*/

NTSYSAPI
NTSTATUS
NTAPI
NtRequestWaitReplyPort(
    IN  HANDLE PortHandle,
    IN  PPORT_MESSAGE RequestMessage,
    OUT PPORT_MESSAGE ReplyMessage
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwRequestWaitReplyPort(
    IN  HANDLE PortHandle,
    IN  PPORT_MESSAGE RequestMessage,
    OUT PPORT_MESSAGE ReplyMessage
    );


/*++

    NtReplyPort
    ===========

    Sends a reply message to a port (Server side)

    PortHandle - A handle to a port object. The handle doesn't need
        to grant any specific access.

    ReplyMessage - Points to a caller-allocated buffer or variable
        that specifies the reply message to send to the port.

--*/

NTSYSAPI
NTSTATUS
NTAPI
NtReplyPort(
    IN  HANDLE PortHandle,
    IN  PPORT_MESSAGE ReplyMessage
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwReplyPort(
    IN  HANDLE PortHandle,
    IN  PPORT_MESSAGE ReplyMessage
    );

/*++

    NtReplyWaitReplyPort
    ====================

    Sends a reply message to a port and waits for a reply message

    PortHandle - A handle to a port object. The handle doesn't need
        to grant any specific access.

    ReplyMessage - Points to a caller-allocated buffer or variable
        that specifies the reply message to send to the port.

--*/

NTSYSAPI
NTSTATUS
NTAPI
NtReplyWaitReplyPort(
    IN  HANDLE PortHandle,
    IN  OUT PPORT_MESSAGE ReplyMessage
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwReplyWaitReplyPort(
    IN  HANDLE PortHandle,
    IN  OUT PPORT_MESSAGE ReplyMessage
    );

/*++

    NtReplyWaitReceivePort
    ======================

    Optionally sends a reply message to a port and waits for a
    message

    PortHandle - A handle to a port object. The handle doesn't need
        to grant any specific access.

    PortContext - Optionally points to a variable that receives
        a numeric identifier associated with the port.

    ReplyMessage - Optionally points to a caller-allocated buffer
        or variable that specifies the reply message to send to the port.

    ReceiveMessage - Points to a caller-allocated buffer or variable
        that receives the message sent to the port.

--*/

NTSYSAPI
NTSTATUS
NTAPI
NtReplyWaitReceivePort(
    IN  HANDLE PortHandle,
    OUT PVOID *PortContext OPTIONAL,
    IN  PPORT_MESSAGE ReplyMessage OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwReplyWaitReceivePort(
    IN  HANDLE PortHandle,
    OUT PVOID *PortContext OPTIONAL,
    IN  PPORT_MESSAGE ReplyMessage OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage
    );

//-----------------------------------------------------------------------------
// Heap functions

#define HEAP_NO_SERIALIZE               0x00000001
#define HEAP_GROWABLE                   0x00000002
#define HEAP_GENERATE_EXCEPTIONS        0x00000004
#define HEAP_ZERO_MEMORY                0x00000008
#define HEAP_REALLOC_IN_PLACE_ONLY      0x00000010
#define HEAP_TAIL_CHECKING_ENABLED      0x00000020
#define HEAP_FREE_CHECKING_ENABLED      0x00000040
#define HEAP_DISABLE_COALESCE_ON_FREE   0x00000080
#define HEAP_CREATE_ALIGN_16            0x00010000
#define HEAP_CREATE_ENABLE_TRACING      0x00020000
#define HEAP_MAXIMUM_TAG                0x0FFF
#define HEAP_PSEUDO_TAG_FLAG            0x8000

//
// Data structure for heap definition. This includes various
// sizing parameters and callback routines, which, if left NULL,
// result in default behavior
//

typedef struct RTL_HEAP_PARAMETERS {
    ULONG Length;        //sizeof(RTL_HEAP_PARAMETERS)
    ULONG SegmentReserve;
    ULONG SegmentCommit;
    ULONG DeCommitFreeBlockThreshold;
    ULONG DeCommitTotalFreeThreshold;
    ULONG MaximumAllocationSize;
    ULONG VirtualMemoryThreshold;
    ULONG InitialCommit;
    ULONG InitialReserve;
    PVOID CommitRoutine;
    ULONG Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

#define RtlProcessHeap() (HANDLE)(NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap)

NTSYSAPI
HANDLE
NTAPI
RtlCreateHeap (
    IN ULONG Flags,
    IN PVOID BaseAddress OPTIONAL,
    IN ULONG SizeToReserve,
    IN ULONG SizeToCommit,
    IN BOOLEAN Lock OPTIONAL,
    IN PRTL_HEAP_PARAMETERS Definition OPTIONAL
    );

NTSYSAPI
ULONG
NTAPI
RtlCreateTagHeap(
    IN PVOID HeapHandle,
    IN ULONG Flags,
    IN PWSTR TagPrefix OPTIONAL,
    IN PWSTR TagNames
    );

NTSYSAPI
ULONG
NTAPI
RtlDestroyHeap (
    IN HANDLE HeapHandle
    );

NTSYSAPI
PVOID
NTAPI
RtlAllocateHeap (
    IN HANDLE HeapHandle,
    IN ULONG Flags,
    IN SIZE_T Size
    );

NTSYSAPI
PVOID
NTAPI
RtlReAllocateHeap (
    IN HANDLE HeapHandle,
    IN ULONG Flags,
    IN LPVOID Address,
    IN SIZE_T Size
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlFreeHeap (
    IN HANDLE HeapHandle,
    IN ULONG Flags,
    IN PVOID Address
    );

NTSYSAPI
ULONG
NTAPI
RtlCompactHeap (
    IN HANDLE HeapHandle,
    IN ULONG Flags
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlLockHeap (
    IN HANDLE HeapHandle
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlUnlockHeap (
    IN HANDLE HeapHandle
    );

NTSYSAPI
ULONG
NTAPI
RtlSizeHeap (
    IN HANDLE HeapHandle,
    IN ULONG Flags,
    IN PVOID Address
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlValidateHeap (
    IN HANDLE HeapHandle,
    IN ULONG Flags,
    IN PVOID Address OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryHeapInformation (
    IN PVOID HeapHandle,
    IN HEAP_INFORMATION_CLASS HeapInformationClass,
    OUT PVOID HeapInformation OPTIONAL,
    IN SIZE_T HeapInformationLength OPTIONAL,
    OUT PSIZE_T ReturnLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlSetHeapInformation (
    IN PVOID HeapHandle,
    IN HEAP_INFORMATION_CLASS HeapInformationClass,
    IN PVOID HeapInformation OPTIONAL,
    IN SIZE_T HeapInformationLength OPTIONAL
    );

//-----------------------------------------------------------------------------
// Virtual memory functions

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,                 // 0x00 MEMORY_BASIC_INFORMATION
    MemoryWorkingSetList,
    MemorySectionName,                      // 0x02 UNICODE_STRING
    MemoryBasicVlmInformation,
    MemoryWorkingSetInfoListInformatiom     // 0x04 Array of {[in]Offset, [out]Flags} to receive the image information
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_WORKING_SET_ENTRY
{
    PVOID Address;
    ULONG Flags;
} MEMORY_WORKING_SET_ENTRY, *PMEMORY_WORKING_SET_ENTRY;

NTSYSAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwAllocateVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
    );

NTSYSAPI
NTSTATUS
NTAPI
NtFreeVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwFreeVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
    );

NTSYSAPI
NTSTATUS
NTAPI
NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
    );

NTSYSAPI
NTSTATUS
NTAPI
NtReadVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwReadVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtFlushVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    OUT PIO_STATUS_BLOCK IoStatus
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwFlushVirtualMemory (
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PSIZE_T RegionSize,
    OUT PIO_STATUS_BLOCK IoStatus
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL
    );

//-----------------------------------------------------------------------------
// Section functions

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2

} SECTION_INHERIT;


typedef enum _SECTION_INFORMATION_CLASS
{
    SectionBasicInformation,
    SectionImageInformation

} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;


/*++

    NtCreateSection
    ===============

    Creates a section object.

    SectionHandle - Points to a variable that will receive the section
        object handle if the call is successful.

    DesiredAccess - Specifies the type of access that the caller requires
        to the section object. This parameter can be zero, or any combination
        of the following flags:

        SECTION_QUERY       - Query access
        SECTION_MAP_WRITE   - Can be written when mapped
        SECTION_MAP_READ    - Can be read when mapped
        SECTION_MAP_EXECUTE - Can be executed when mapped
        SECTION_EXTEND_SIZE - Extend access
        SECTION_ALL_ACCESS  - All of the preceding +
                              STANDARD_RIGHTS_REQUIRED

    ObjectAttributes - Points to a structure that specifies the object�s attributes.
        OBJ_OPENLINK is not a valid attribute for a section object.

    MaximumSize - Optionally points to a variable that specifies the size,
        in bytes, of the section. If FileHandle is zero, the size must be
        specified; otherwise, it can be defaulted from the size of the file
        referred to by FileHandle.

    SectionPageProtection - The protection desired for the pages
        of the section when the section is mapped. This parameter can take
        one of the following values:

        PAGE_READONLY
        PAGE_READWRITE
        PAGE_WRITECOPY
        PAGE_EXECUTE
        PAGE_EXECUTE_READ
        PAGE_EXECUTE_READWRITE
        PAGE_EXECUTE_WRITECOPY

    AllocationAttributes - The attributes for the section. This parameter must
        be a combination of the following values:

        SEC_BASED     0x00200000    // Map section at same address in each process
        SEC_NO_CHANGE 0x00400000    // Disable changes to protection of pages
        SEC_IMAGE     0x01000000    // Map section as an image
        SEC_VLM       0x02000000    // Map section in VLM region
        SEC_RESERVE   0x04000000    // Reserve without allocating pagefile storage
        SEC_COMMIT    0x08000000    // Commit pages; the default behavior
        SEC_NOCACHE   0x10000000    // Mark pages as non-cacheable

    FileHandle - Identifies the file from which to create the section object.
        The file must be opened with an access mode compatible with the protection
        flags specified by the Protect parameter. If FileHandle is zero,
        the function creates a section object of the specified size backed
        by the paging file rather than by a named file in the file system.

--*/

NTSYSAPI
NTSTATUS
NTAPI
NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN  PLARGE_INTEGER MaximumSize OPTIONAL,
    IN  ULONG SectionPageProtection,
    IN  ULONG AllocationAttributes,
    IN  HANDLE FileHandle OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwCreateSection(
    OUT PHANDLE SectionHandle,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN  PLARGE_INTEGER MaximumSize OPTIONAL,
    IN  ULONG SectionPageProtection,
    IN  ULONG AllocationAttributes,
    IN  HANDLE FileHandle OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenSection (
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenSection (
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
NtMapViewOfSection (
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Protect
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwMapViewOfSection (
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN ULONG CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PULONG ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Protect
    );

NTSYSAPI
NTSTATUS
NTAPI
NtUnmapViewOfSection (
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwUnmapViewOfSection (
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
    );

NTSYSAPI
NTSTATUS
NTAPI
NtExtendSection (
    IN HANDLE SectionHandle,
    IN OUT PLARGE_INTEGER SectionSize
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwExtendSection (
    IN HANDLE SectionHandle,
    IN OUT PLARGE_INTEGER SectionSize
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySection (
    IN HANDLE SectionHandle,
    IN SECTION_INFORMATION_CLASS SectionInformationClass,
    OUT PVOID SectionInformation,
    IN SIZE_T Length,
    OUT PSIZE_T ResultLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySection (
    IN HANDLE SectionHandle,
    IN SECTION_INFORMATION_CLASS SectionInformationClass,
    OUT PVOID SectionInformation,
    IN SIZE_T Length,
    OUT PSIZE_T ResultLength OPTIONAL
    );


//-----------------------------------------------------------------------------
// Synchronization

//
// Wait type
//

typedef enum _WAIT_TYPE {
    WaitAll,
    WaitAny
    } WAIT_TYPE;

NTSYSAPI
NTSTATUS
NTAPI
NtWaitForSingleObject (
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwWaitForSingleObject (
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtWaitForMultipleObjects (
    IN ULONG Count,
    IN HANDLE Handle[],
    IN WAIT_TYPE WaitType,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwWaitForMultipleObjects (
    IN ULONG Count,
    IN HANDLE Handle[],
    IN WAIT_TYPE WaitType,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL
    );


//-----------------------------------------------------------------------------
// Event support

typedef enum _EVENT_INFORMATION_CLASS {
    EventBasicInformation    // = 0
} EVENT_INFORMATION_CLASS;

typedef struct _EVENT_BASIC_INFORMATION {
    EVENT_TYPE EventType;
    LONG EventState;
} EVENT_BASIC_INFORMATION, *PEVENT_BASIC_INFORMATION;

//
// Event handling routines
//

NTSYSAPI
NTSTATUS
NTAPI
NtCreateEvent (
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN EVENT_TYPE EventType,
    IN BOOLEAN InitialState
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwCreateEvent (
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN EVENT_TYPE EventType,
    IN BOOLEAN InitialState
    );

NTSYSAPI
NTSTATUS
NTAPI
NtClearEvent (
    IN HANDLE Handle
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwClearEvent (
    IN HANDLE Handle
    );

NTSYSAPI
NTSTATUS
NTAPI
NtPulseEvent (
    IN HANDLE Handle,
    OUT PLONG PreviousState OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwPulseEvent (
    IN HANDLE Handle,
    OUT PLONG PreviousState OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtResetEvent (
    IN HANDLE Handle,
    OUT PLONG PreviousState OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwResetEvent (
    IN HANDLE Handle,
    OUT PLONG PreviousState OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetEvent (
    IN HANDLE Handle,
    OUT PLONG PreviousState OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwSetEvent (
    IN HANDLE Handle,
    OUT PLONG PreviousState OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenEvent (
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwOpenEvent (
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryEvent (
    IN HANDLE EventHandle,
    IN EVENT_INFORMATION_CLASS EventInfoClass,
    OUT PVOID EventInfo,
    IN ULONG Length,
    OUT PULONG ResultLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryEvent (
    IN HANDLE EventHandle,
    IN EVENT_INFORMATION_CLASS EventInfoClass,
    OUT PVOID EventInfo,
    IN ULONG Length,
    OUT PULONG ResultLength OPTIONAL
    );

//-----------------------------------------------------------------------------
// Mutant support

NTSYSAPI
NTSTATUS
NTAPI
NtCreateMutant(
    OUT PHANDLE MutantHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN BOOLEAN InitialOwner
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenMutant(
    OUT PHANDLE MutantHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtReleaseMutant(
    IN HANDLE MutantHandle,
    IN PLONG PreviousCount OPTIONAL
    );

//-----------------------------------------------------------------------------
// Semaphore support

NTSYSAPI
NTSTATUS
NTAPI
NtCreateSemaphore(
    OUT PHANDLE SemaphoreHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN ULONG InitialCount,
    IN ULONG MaximumCount
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenSemaphore(
    OUT PHANDLE SemaphoreHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    );

//-----------------------------------------------------------------------------
// EventPair support

#define EVENT_PAIR_ALL_ACCESS ( STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE )

NTSYSAPI
NTSTATUS
NTAPI
NtCreateEventPair(
    OUT PHANDLE EventPairHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenEventPair(
    OUT PHANDLE EventPairHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL
    );


//-----------------------------------------------------------------------------
// Security descriptor functions

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateSecurityDescriptor (
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN ULONG Revision
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlAbsoluteToSelfRelativeSD(
    IN PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    IN OUT PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    IN OUT PULONG BufferLength
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlSelfRelativeToAbsoluteSD(
    IN OUT PSECURITY_DESCRIPTOR SelfRelativeSecurityDescriptor,
    OUT PSECURITY_DESCRIPTOR AbsoluteSecurityDescriptor,
    IN OUT PULONG AbsoluteSecurityDescriptorSize,
    IN OUT PACL Dacl,
    IN OUT PULONG DaclSize,
    IN OUT PACL Sacl,
    IN OUT PULONG SaclSize,
    IN OUT PSID Owner,
    IN OUT PULONG OwnerSize,
    IN OUT PSID PrimaryGroup,
    IN OUT PULONG PrimaryGroupSize
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlGetOwnerSecurityDescriptor(
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    OUT PSID *Owner,
    OUT PBOOLEAN OwnerDefaulted
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlSetOwnerSecurityDescriptor(
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN PSID Owner OPTIONAL,
    IN BOOLEAN OwnerDefaulted OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlGetGroupSecurityDescriptor(
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    OUT PSID *Group,
    OUT PBOOLEAN GroupDefaulted
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlSetGroupSecurityDescriptor(
    IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN PSID Group OPTIONAL,
    IN BOOLEAN GroupDefaulted OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlGetDaclSecurityDescriptor(
    IN PSECURITY_DESCRIPTOR  SecurityDescriptor,
    OUT PBOOLEAN  DaclPresent,
    OUT PACL  *Dacl,
    OUT PBOOLEAN  DaclDefaulted
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlSetDaclSecurityDescriptor(
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN BOOLEAN DaclPresent,
    IN PACL Dacl OPTIONAL,
    IN BOOLEAN DaclDefaulted OPTIONAL
    );


NTSTATUS
RtlGetSaclSecurityDescriptor(
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    OUT PBOOLEAN SaclPresent,
    OUT PACL *Sacl,
    OUT PBOOLEAN SaclDefaulted
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlSetSaclSecurityDescriptor(
    IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN BOOLEAN SaclPresent,
    IN PACL Sacl,
    IN BOOLEAN SaclDefaulted
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlAllocateAndInitializeSid(
    IN PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
    IN UCHAR SubAuthorityCount,
    IN ULONG SubAuthority0,
    IN ULONG SubAuthority1,
    IN ULONG SubAuthority2,
    IN ULONG SubAuthority3,
    IN ULONG SubAuthority4,
    IN ULONG SubAuthority5,
    IN ULONG SubAuthority6,
    IN ULONG SubAuthority7,
    OUT PSID *Sid
    );

NTSYSAPI
ULONG
NTAPI
RtlLengthSid(
    IN PSID Sid
    );

NTSYSAPI
BOOLEAN
NTAPI
RtlEqualSid(
    IN PSID Sid1,
    IN PSID Sid2
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlConvertSidToUnicodeString(
    OUT PUNICODE_STRING UnicodeString,
    IN  PSID Sid,
    IN  BOOLEAN AllocateDestinationString
    );

NTSYSAPI
PVOID
NTAPI
RtlFreeSid(
    IN PSID Sid
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateAcl(
    IN PACL Acl,
    IN ULONG AclLength,
    IN ULONG AclRevision
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlGetAce(
    IN PACL Acl,
    IN ULONG AceIndex,
    OUT PVOID  *Ace
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedAce(
    IN OUT PACL Acl,
    IN ULONG AceRevision,
    IN ACCESS_MASK AccessMask,
    IN PSID Sid
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlAddAccessAllowedAceEx(
    IN OUT PACL Acl,
    IN ULONG AceRevision,
    IN ULONG AceFlags,
    IN ULONG AccessMask,
    IN PSID Sid
    );

//-----------------------------------------------------------------------------
// Token functions

NTSYSAPI
NTSTATUS
NTAPI
NtOpenProcessToken(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PHANDLE TokenHandle
    );

// Windows XP or newer
NTSYSAPI
NTSTATUS
NTAPI
NtOpenProcessTokenEx(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    OUT PHANDLE TokenHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenThreadToken(
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN BOOLEAN OpenAsSelf,
    OUT PHANDLE TokenHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationToken(
    IN HANDLE  TokenHandle,
    IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
    OUT PVOID  TokenInformation,
    IN ULONG  TokenInformationLength,
    OUT PULONG  ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationToken(
    IN HANDLE  TokenHandle,
    IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
    OUT PVOID  TokenInformation,
    IN ULONG  TokenInformationLength,
    OUT PULONG  ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtSetInformationToken(
    IN HANDLE  TokenHandle,
    IN TOKEN_INFORMATION_CLASS  TokenInformationClass,
    IN PVOID  TokenInformation,
    IN ULONG  TokenInformationLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtAdjustPrivilegesToken(
    IN HANDLE TokenHandle,
    IN BOOLEAN DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES NewState OPTIONAL,
    IN ULONG BufferLength OPTIONAL,
    IN PTOKEN_PRIVILEGES PreviousState OPTIONAL,
    OUT PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtDuplicateToken(
    IN HANDLE ExistingTokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN EffectiveOnly,
    IN TOKEN_TYPE TokenType,
    OUT PHANDLE NewTokenHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
NtCompareTokens(
    IN  HANDLE FirstTokenHandle,
    IN  HANDLE SecondTokenHandle,
    OUT PBOOLEAN IdenticalTokens
    );

//-----------------------------------------------------------------------------
// Token functions available from Windows 8.1

// Token security attribute type
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_INVALID 0x00
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_INT64 0x01
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_UINT64 0x02
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_STRING 0x03
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_FQBN 0x04
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_SID 0x05
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_BOOLEAN 0x06
#define TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING 0x10

// Token security attribute flags
#define TOKEN_SECURITY_ATTRIBUTE_NON_INHERITABLE 0x0001
#define TOKEN_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE 0x0002
#define TOKEN_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY 0x0004
#define TOKEN_SECURITY_ATTRIBUTE_DISABLED_BY_DEFAULT 0x0008
#define TOKEN_SECURITY_ATTRIBUTE_DISABLED 0x0010
#define TOKEN_SECURITY_ATTRIBUTE_MANDATORY 0x0020

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
    ULONG64 Version;
    UNICODE_STRING Name;

} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
    PVOID pValue;
    ULONG ValueLength;

} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
    UNICODE_STRING Name;
    USHORT ValueType;
    USHORT Reserved;
    ULONG  Flags;
    ULONG  ValueCount;

    union
    {
        PLONG64 pInt64;
        PULONG64 pUint64;
        PUNICODE_STRING pString;
        PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE pFqbn;
        PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
    } Values;

} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
    USHORT Version;
    USHORT Reserved;
    ULONG AttributeCount;

    union
    {
        PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
    } Attribute;

} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySecurityAttributesToken(
    IN  HANDLE TokenHandle,
    IN  PUNICODE_STRING Attributes,
    IN  ULONG NumberOfAttributes,
    OUT PVOID Buffer,
    IN  ULONG Length,
    OUT PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySecurityAttributesToken(
    IN  HANDLE TokenHandle,
    IN  PUNICODE_STRING Attributes,
    IN  ULONG NumberOfAttributes,
    OUT PVOID Buffer,
    IN  ULONG Length,
    OUT PULONG ReturnLength
    );

//-----------------------------------------------------------------------------
// Symbolic links

//
// Object Manager Symbolic Link Specific Access Rights.
//

#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY (0x0001)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)
#endif

NTSYSAPI
NTSTATUS
NTAPI
NtCreateDirectoryObjectEx( OUT PHANDLE SymbolicLinkHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ShadowDir, ULONG Something );

NTSYSAPI
NTSTATUS
NTAPI
NtCreateSymbolicLinkObject(
    OUT PHANDLE SymbolicLinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PUNICODE_STRING DestinationName
    );

NTSYSAPI
NTSTATUS
NTAPI
NtOpenSymbolicLinkObject (
    OUT PHANDLE SymbolicLinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySymbolicLinkObject (
    IN HANDLE SymbolicLinkHandle,
    OUT PUNICODE_STRING NameString,
    OUT PULONG ResultLength OPTIONAL
    );

//-----------------------------------------------------------------------------
// Loader functions

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    IN PVOID Base
    );

#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK (0x00000001)
#define RTL_IMAGE_NT_HEADER_EX_FLAG_UNKNONW_W10    (0x00000002)     // Used to call RtlImageNtHeaderEx in W10, but never checked

NTSYSAPI
NTSTATUS
NTAPI
RtlImageNtHeaderEx(
    ULONG Flags,
    PVOID Base,
    ULONG64 Size,
    OUT PIMAGE_NT_HEADERS * OutHeaders
    );

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    IN PVOID Base,
    IN BOOLEAN MappedAsImage,
    IN USHORT DirectoryEntry,
    OUT PULONG Size
    );

NTSYSAPI
PVOID
NTAPI
RtlImageRvaToVa(
    IN PIMAGE_NT_HEADERS NtHeaders,
    IN PVOID Base,
    IN ULONG Rva,
    IN OUT PIMAGE_SECTION_HEADER *LastRvaSection OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrLoadDll(
    IN PWSTR DllPath OPTIONAL,
    IN PULONG DllCharacteristics OPTIONAL,
    IN PUNICODE_STRING DllName,
    OUT PVOID *DllHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandle(
    IN PWSTR DllPath OPTIONAL,
    IN PULONG DllCharacteristics OPTIONAL,
    IN PUNICODE_STRING DllName,
    OUT PVOID * DllHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrUnloadDll(
    IN PVOID DllHandle
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddress(
    IN PVOID DllHandle,
    IN PANSI_STRING ProcedureName OPTIONAL,
    IN ULONG ProcedureNumber OPTIONAL,
    OUT PVOID *ProcedureAddress
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrFindResource_U(
    IN PVOID DllHandle,
    IN PULONG_PTR ResourceIdPath,
    IN ULONG ResourceIdPathLength,
    OUT PIMAGE_RESOURCE_DATA_ENTRY *ResourceDataEntry
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrAccessResource(
    IN PVOID DllHandle,
    IN PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry,
    OUT PVOID *Address OPTIONAL,
    OUT PULONG Size OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
LdrDisableThreadCalloutsForDll(
    IN PVOID DllHandle
    );

//-----------------------------------------------------------------------------
// Driver functions

NTSYSAPI
NTSTATUS
NTAPI
NtLoadDriver(
    PUNICODE_STRING DriverServiceName
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwLoadDriver(
    PUNICODE_STRING DriverServiceName
    );

NTSYSAPI
NTSTATUS
NTAPI
NtUnloadDriver(
    PUNICODE_STRING DriverServiceName
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwUnloadDriver(
    PUNICODE_STRING DriverServiceName
    );

//-----------------------------------------------------------------------------
// Functions dealing with NTSTATUS and Win32 error

typedef enum _HARDERROR_RESPONSE_OPTION
{
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem

} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort,
    ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes

} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosError(
    NTSTATUS Status
    );

NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosErrorNoTeb(
    NTSTATUS Status
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlGetLastNtStatus(
    );

NTSYSAPI
ULONG
NTAPI
RtlGetLastWin32Error(
    );

NTSYSAPI
VOID
NTAPI
RtlSetLastWin32Error(
    ULONG WinError
    );

NTSYSAPI
VOID
NTAPI
RtlSetLastWin32ErrorAndNtStatusFromNtStatus(
    NTSTATUS Status
    );

NTSYSAPI
NTSTATUS
NTAPI
NtRaiseHardError(
    IN  NTSTATUS ErrorStatus,
    IN  ULONG NumberOfParameters,
    IN  PUNICODE_STRING UnicodeStringParameterMask OPTIONAL,
    IN  PVOID * Parameters,
    IN  HARDERROR_RESPONSE_OPTION ResponseOption,
    OUT PHARDERROR_RESPONSE Response
    );

//-----------------------------------------------------------------------------
// Other functions

NTSYSAPI
NTSTATUS
NTAPI
NtContinue(
    IN PCONTEXT Context,
    IN BOOLEAN Alertable
    );

NTSYSAPI
NTSTATUS
NTAPI
NtTestAlert(
    );

NTSYSAPI
NTSTATUS
NTAPI
NtQueryPerformanceCounter(
    OUT PLARGE_INTEGER PerformanceCounter,
    OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtAllocateLocallyUniqueId(
    OUT PLUID LocallyUniqueId
    );

NTSYSAPI
NTSTATUS
NTAPI
NtDelayExecution(
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER DelayInterval
    );

NTSYSAPI
NTSTATUS
NTAPI
NtDisplayString(
    IN PUNICODE_STRING String
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlGetVersion(
    PRTL_OSVERSIONINFOW lpVersionInformation
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlGetCurrentDirectory_U(
    ULONG nBufferLength,
    PWSTR lpBuffer
    );

NTSYSAPI
NTSTATUS
NTAPI
NtCreateTransaction(
    PHANDLE            TransactionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    LPGUID             Uow,
    HANDLE             TmHandle,
    ULONG              CreateOptions,
    ULONG              IsolationLevel,
    ULONG              IsolationFlags,
    PLARGE_INTEGER     Timeout,
    PUNICODE_STRING    Description
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // __NTDLL_H__
