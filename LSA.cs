using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using static SslCacheNet.Native;

namespace SslCacheNet
{
    internal class LSA : IDisposable
    {
        const string MUSPProvider = "Microsoft Unified Security Protocol Provider";

        IntPtr _lsaHandle;
        uint _packageNumber;
        bool _trusted;

        public bool IsConnected => _lsaHandle != IntPtr.Zero;

        private void Connect()
        {
            if (IsConnected)
            {
                return;
            }

            //
            // Get handle to schannel security package.
            //

            var ntStatus = Native.RtlAdjustPrivilege(Privilege.SeTcbPrivilege, true, false, out var WasEnabled);
            _trusted = Native.NT_SUCCESS(ntStatus);

            if (_trusted)
            {
                var lsaString = new LSA_STRING();
                lsaString.Buffer = "SslCacheNet";
                lsaString.Length = (ushort)lsaString.Buffer.Length;
                lsaString.MaximumLength = (ushort)(lsaString.Length + 1);

                ntStatus = Native.LsaRegisterLogonProcess(
                            ref lsaString,
                            out _lsaHandle,
                            out var Dummy);

                if (FAILED(ntStatus))
                {
                    throw new Win32Exception(ntStatus, $"{nameof(Native.LsaRegisterLogonProcess)} has failed");
                }
            }
            else
            {
                ntStatus = Native.LsaConnectUntrusted(out _lsaHandle);

                if (Native.FAILED(ntStatus))
                {
                    throw new Win32Exception(ntStatus, $"{nameof(Native.LsaConnectUntrusted)} has failed");
                }
            }

            var PackageName = new Native.LSA_STRING();

            PackageName.Buffer = MUSPProvider;
            PackageName.Length = Convert.ToUInt16(MUSPProvider.Length);
            PackageName.MaximumLength = Convert.ToUInt16(PackageName.Length + 1);

            ntStatus = Native.LsaLookupAuthenticationPackage(_lsaHandle, ref PackageName, out _packageNumber);

            if (Native.FAILED(ntStatus))
            {
                throw new Win32Exception(ntStatus, $"{nameof(Native.LsaLookupAuthenticationPackage)} has failed");
            }
        }

        private void Close()
        {
            if (!IsConnected)
            {
                return;
            }

            if (_lsaHandle != IntPtr.Zero)
            {
                Native.LsaDeregisterLogonProcess(_lsaHandle);
                _lsaHandle = IntPtr.Zero;
                _packageNumber = 0;
            }
        }

        ~LSA()
        {
            Close();
        }

        public void Dispose()
        {
            Close();

            GC.SuppressFinalize(this);
        }

        public Native.SSL_SESSION_CACHE_INFO_RESPONSE GetSessionCacheInfo(bool includeClient, bool includeServer)
        {
            Connect();

            IntPtr responseAllocatedByApi = IntPtr.Zero;

            try
            {
                var sslSessionCacheInfoRequest = new Native.SSL_SESSION_CACHE_INFO_REQUEST();// Marshal.PtrToStructure<Native.SSL_SESSION_CACHE_INFO_REQUEST>(requestAlloc);

                sslSessionCacheInfoRequest.MessageType = Native.SslSessionCacheInfoMessage;

                if (includeClient)
                {
                    sslSessionCacheInfoRequest.Flags |= Native.SSL_RETRIEVE_CLIENT_ENTRIES;
                }

                if (includeServer)
                {
                    sslSessionCacheInfoRequest.Flags |= Native.SSL_RETRIEVE_SERVER_ENTRIES;
                }

                var ntStatus = Native.LsaCallAuthenticationPackage(
                     _lsaHandle,
                     _packageNumber,
                     ref sslSessionCacheInfoRequest,
                     (uint)Marshal.SizeOf(sslSessionCacheInfoRequest),
                     ref responseAllocatedByApi,
                     out var cbResponse,
                     out var ntSubStatus);

                if (Native.FAILED(ntStatus))
                {
                    throw new Win32Exception(ntStatus, $"{nameof(Native.LsaCallAuthenticationPackage)} has failed");
                }

                if (Native.FAILED(ntSubStatus))
                {
                    throw new Win32Exception(ntSubStatus, $"{nameof(Native.LsaCallAuthenticationPackage)} returns an error");
                }

                var sslSessionCacheInfoResponse = Marshal.PtrToStructure<Native.SSL_SESSION_CACHE_INFO_RESPONSE>(responseAllocatedByApi);

                return sslSessionCacheInfoResponse;
            }
            finally
            {
                if (responseAllocatedByApi != IntPtr.Zero)
                {
                    Native.LsaFreeReturnBuffer(responseAllocatedByApi);
                }
            }
        }

        public void PurgeCacheEntries(bool includeClient, bool includeServer, bool includeMappedEntries, string pszServerName)
        {
            Connect();

            IntPtr requestAlloc = IntPtr.Zero;

            try
            {
                Console.WriteLine("\nPURGE CACHE ENTRIES");
                Console.WriteLine("Client:{0}", includeClient ? "yes" : "no");
                Console.WriteLine("Server:{0}", includeServer ? "yes" : "no");

                var cbSize = Marshal.SizeOf<Native.SSL_PURGE_SESSION_CACHE_REQUEST>();

                int cbServerName = (pszServerName?.Length ?? 0);

                if (cbServerName > 0)
                {
                    cbServerName += 2;
                    cbServerName *= sizeof(char);
                }

                requestAlloc = Marshal.AllocHGlobal(cbSize + cbServerName);

                if (requestAlloc == null)
                {
                    Console.WriteLine("**** Out of memory");
                    return;
                }

                var sslPurgeSessionCacheRequest = new Native.SSL_PURGE_SESSION_CACHE_REQUEST();

                if (cbServerName > 0)
                {
                    var bytes = Encoding.Unicode.GetBytes(pszServerName + "\0\0");
                    IntPtr dstServerName = requestAlloc + cbSize;
                    Marshal.Copy(bytes, 0, dstServerName, bytes.Length);

                    //Buffer has to be just after the structure
                    //struct SSL_PURGE_SESSION_CACHE_REQUEST;ServerNamebuffer
                    sslPurgeSessionCacheRequest.ServerName.Buffer = dstServerName;
                    sslPurgeSessionCacheRequest.ServerName.Length = (ushort)(cbServerName - sizeof(char));
                    sslPurgeSessionCacheRequest.ServerName.MaximumLength = (ushort)cbServerName;
                }

                sslPurgeSessionCacheRequest.MessageType = SslPurgeSessionCacheMessage;

                if (includeClient)
                {
                    //sslPurgeSessionCacheRequest.Flags |= SSL_PURGE_CLIENT_ENTRIES;
                    sslPurgeSessionCacheRequest.Flags |= SSL_PURGE_CLIENT_ALL_ENTRIES;
                }
                if (includeServer)
                {
                    //sslPurgeSessionCacheRequest.Flags |= SSL_PURGE_SERVER_ENTRIES;
                    sslPurgeSessionCacheRequest.Flags |= SSL_PURGE_SERVER_ALL_ENTRIES;
                }
                if (includeMappedEntries)
                {
                    sslPurgeSessionCacheRequest.Flags |= SSL_PURGE_SERVER_ENTRIES_DISCARD_LOCATORS;
                }

                var sizeofRequest = Marshal.SizeOf(sslPurgeSessionCacheRequest) + cbServerName;
                IntPtr nullPtr = IntPtr.Zero;

                //copy structure to memory back
                Marshal.StructureToPtr<Native.SSL_PURGE_SESSION_CACHE_REQUEST>(sslPurgeSessionCacheRequest, requestAlloc, false);

                var ntStatus = LsaCallAuthenticationPackage(
                                    _lsaHandle,
                                    _packageNumber,
                                    requestAlloc,
                                    (uint)sizeofRequest,
                                    ref nullPtr,
                                    out var dwReturnCode,
                                    out var ntSubStatus);

                Console.WriteLine("Status: 0x{0:X8}", ntStatus);
                Console.WriteLine("SubStatus: 0x{0:X8}", (int)ntSubStatus);

                if (FAILED(ntStatus))
                {
                    throw new Win32Exception(ntStatus, $"{nameof(Native.LsaCallAuthenticationPackage)} has failed");
                }

                if (FAILED((int)ntSubStatus))
                {
                    if (ntSubStatus == Native.NtSubStatus.STATUS_PRIVILEGE_NOT_HELD)
                    {
                        throw new Exception("**** The TCB privilege is required to perform this operation.\n");
                    }
                    else
                    {
                        throw new Exception(string.Format($"**** Error {ntSubStatus} occurred while purging cache entries.\n", ntSubStatus));
                    }
                }
            }
            finally
            {
                if (requestAlloc != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(requestAlloc);
                }
            }
        }

    }
}