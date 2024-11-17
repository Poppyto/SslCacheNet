using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static SslCacheNet.Native;

namespace SslCacheNet
{
    internal class Native
    {

        #region Methods

        [DllImport("SECUR32.dll")]
        internal static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("SECUR32.dll")]
        internal static extern int LsaDeregisterLogonProcess(IntPtr LsaHandle);

        [DllImport("SECUR32.dll", ExactSpelling = true)]
        internal static extern int LsaLookupAuthenticationPackage(IntPtr LsaHandle, ref LSA_STRING PackageName, out uint AuthenticationPackage);

        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [DllImport("SECUR32.dll", ExactSpelling = true)]
        internal static extern int LsaFreeReturnBuffer(IntPtr Buffer);

        [DllImport("SECUR32.dll", ExactSpelling = true)]
        internal static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle, uint AuthenticationPackage, ref SSL_SESSION_CACHE_INFO_REQUEST ProtocolSubmitBuffer, uint SubmitBufferLength, ref IntPtr ProtocolReturnBuffer, out uint ReturnBufferLength, out int ProtocolStatus);

        [DllImport("SECUR32.dll", ExactSpelling = true)]
        internal static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle, uint AuthenticationPackage, IntPtr ProtocolSubmitBuffer, uint SubmitBufferLength, ref IntPtr ProtocolReturnBuffer, out uint ReturnBufferLength, out NtSubStatus ProtocolStatus);
        
        [DllImport("SECUR32.dll", ExactSpelling = true)]
        internal static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle, uint AuthenticationPackage, ref SSL_PERFMON_INFO_REQUEST ProtocolSubmitBuffer, uint SubmitBufferLength, ref IntPtr ProtocolReturnBuffer, out uint ReturnBufferLength, out int ProtocolStatus);


        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr LocalAlloc(LOCAL_ALLOC_FLAGS uFlags, UIntPtr uBytes);

        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern int RtlAdjustPrivilege(Privilege privilege, bool bEnablePrivilege, bool IsThreadPrivilege, out bool PreviousValue);

        [DllImport("SECUR32.dll", ExactSpelling = true)]
        internal static extern int LsaRegisterLogonProcess(ref LSA_STRING lsaString, out IntPtr LsaHandle, out uint SecurityMode);



        #endregion

        internal static bool FAILED(int hr)
        {
            return ((int)hr) < 0;
        }

        internal static bool NT_SUCCESS(int hr)
        {
            return ((int)hr) >= 0;
        }

        #region Flags

        [Flags]
        internal enum LOCAL_ALLOC_FLAGS : uint
        {
            LHND = 0x00000042,
            LMEM_FIXED = 0x00000000,
            LMEM_MOVEABLE = 0x00000002,
            LMEM_ZEROINIT = 0x00000040,
            LPTR = 0x00000040,
            NONZEROLHND = 0x00000002,
            NONZEROLPTR = 0x00000000,
        }

        internal enum Privilege : int
        {
            SeCreateTokenPrivilege = 1,
            SeAssignPrimaryTokenPrivilege = 2,
            SeLockMemoryPrivilege = 3,
            SeIncreaseQuotaPrivilege = 4,
            SeUnsolicitedInputPrivilege = 5,
            SeMachineAccountPrivilege = 6,
            SeTcbPrivilege = 7,
            SeSecurityPrivilege = 8,
            SeTakeOwnershipPrivilege = 9,
            SeLoadDriverPrivilege = 10,
            SeSystemProfilePrivilege = 11,
            SeSystemtimePrivilege = 12,
            SeProfileSingleProcessPrivilege = 13,
            SeIncreaseBasePriorityPrivilege = 14,
            SeCreatePagefilePrivilege = 15,
            SeCreatePermanentPrivilege = 16,
            SeBackupPrivilege = 17,
            SeRestorePrivilege = 18,
            SeShutdownPrivilege = 19,
            SeDebugPrivilege = 20,
            SeAuditPrivilege = 21,
            SeSystemEnvironmentPrivilege = 22,
            SeChangeNotifyPrivilege = 23,
            SeRemoteShutdownPrivilege = 24,
            SeUndockPrivilege = 25,
            SeSyncAgentPrivilege = 26,
            SeEnableDelegationPrivilege = 27,
            SeManageVolumePrivilege = 28,
            SeImpersonatePrivilege = 29,
            SeCreateGlobalPrivilege = 30,
            SeTrustedCredManAccessPrivilege = 31,
            SeRelabelPrivilege = 32,
            SeIncreaseWorkingSetPrivilege = 33,
            SeTimeZonePrivilege = 34,
            SeCreateSymbolicLinkPrivilege = 35
        }
        //https://ntoskrnl.org/
        internal enum NtSubStatus : int
        {
            STATUS_QUOTA_EXCEEDED = unchecked((int)0xC0000044),
            STATUS_NO_SUCH_PACKAGE = unchecked((int)0xC00000FE),
            STATUS_PKINIT_FAILURE = unchecked((int)0xC0000320),
            STATUS_PKINIT_CLIENT_FAILURE = unchecked((int)0xC000038C),
            STATUS_PRIVILEGE_NOT_HELD = unchecked((int)0xC0000061),
            STATUS_INVALID_PARAMETER = unchecked((int)0xC000000D)
        }

        #endregion

        #region Structures


        [StructLayout(LayoutKind.Sequential)]
        internal struct LSA_STRING
        {
            internal ushort Length;
            internal ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPStr)]
            internal string Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID
        {
            uint LowPart;
            uint HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SSL_SESSION_CACHE_INFO_REQUEST
        {
            internal uint MessageType;
            internal LUID LogonId;
            internal UNICODE_STRING ServerName;
            internal uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING_WOW64
        {
            internal ushort Length;
            internal ushort MaximumLength;

            [MarshalAs(UnmanagedType.LPStr)]
            internal string Buffer;
        }
        

        [StructLayout(LayoutKind.Sequential)]
        internal struct SSL_SESSION_CACHE_INFO_RESPONSE
        {
            internal uint CacheSize;
            internal uint Entries;
            internal uint ActiveEntries;
            internal uint Zombies;
            internal uint ExpiredZombies;
            internal uint AbortedZombies;
            internal uint DeletedZombies;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SSL_PURGE_SESSION_CACHE_REQUEST
        {
            internal uint MessageType;
            internal LUID LogonId;
            internal UNICODE_STRING ServerName;
            internal uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SSL_PERFMON_INFO_REQUEST
        {
            internal uint MessageType;
            internal uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SSL_PERFMON_INFO_RESPONSE
        {
            internal uint ClientCacheEntries;
            internal uint ServerCacheEntries;
            internal uint ClientActiveEntries;
            internal uint ServerActiveEntries;
            internal uint ClientHandshakesPerSecond;
            internal uint ServerHandshakesPerSecond;
            internal uint ClientReconnectsPerSecond;
            internal uint ServerReconnectsPerSecond;
        }

        #endregion

        #region Constants

        internal const int SSL_LOOKUP_CERT_MESSAGE = 2;
        internal const int SSL_PURGE_CACHE_MESSAGE = 3;
        internal const int SSL_CACHE_INFO_MESSAGE = 4;
        internal const int SSL_PERFMON_INFO_MESSAGE = 5;
        internal const int SSL_LOOKUP_EXTERNAL_CERT_MESSAGE = 6;
        internal const int SslPurgeSessionCacheMessage = SSL_PURGE_CACHE_MESSAGE;
        internal const int SslSessionCacheInfoMessage = SSL_CACHE_INFO_MESSAGE;
        internal const int SSL_RETRIEVE_CLIENT_ENTRIES = 0x00000001;
        internal const int SSL_RETRIEVE_SERVER_ENTRIES = 0x00000002;
        internal const int SSL_PURGE_CLIENT_ENTRIES = 0x00000001;
        internal const int SSL_PURGE_SERVER_ENTRIES = 0x00000002;
        internal const int SSL_PURGE_CLIENT_ALL_ENTRIES = 0x00010000; // test use only
        internal const int SSL_PURGE_SERVER_ALL_ENTRIES = 0x00020000; // test use only
        internal const int SSL_PURGE_SERVER_ENTRIES_DISCARD_LOCATORS = 0x00040000; // test use only

        #endregion
    }
}
