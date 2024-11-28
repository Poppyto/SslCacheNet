using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
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
                lsaString.Buffer = Environment.GetCommandLineArgs()[0]; //SslCacheNet
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
            }

            _packageNumber = 0;
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

        public void PurgeCacheEntries(bool includeClient, bool includeServer)
        {
            Connect();

            IntPtr requestAlloc = IntPtr.Zero;

            try
            {
                var cbSize = Marshal.SizeOf<Native.SSL_PURGE_SESSION_CACHE_REQUEST>();

                requestAlloc = Marshal.AllocHGlobal(cbSize);

                if (requestAlloc == IntPtr.Zero)
                {
                    throw new OutOfMemoryException("**** Out of memory");
                }

                var sslPurgeSessionCacheRequest = new Native.SSL_PURGE_SESSION_CACHE_REQUEST();

                sslPurgeSessionCacheRequest.MessageType = SslPurgeSessionCacheMessage;

                if (includeClient)
                {
                    sslPurgeSessionCacheRequest.Flags |= SSL_PURGE_CLIENT_ENTRIES | SSL_PURGE_CLIENT_ALL_ENTRIES;
                }

                if (includeServer)
                {
                    sslPurgeSessionCacheRequest.Flags |= SSL_PURGE_SERVER_ENTRIES | SSL_PURGE_SERVER_ALL_ENTRIES;
                }

                var sizeofRequest = Marshal.SizeOf(sslPurgeSessionCacheRequest);
                IntPtr nullPtr = IntPtr.Zero;

                //copy structure to memory
                Marshal.StructureToPtr<Native.SSL_PURGE_SESSION_CACHE_REQUEST>(sslPurgeSessionCacheRequest, requestAlloc, false);

                var ntStatus = LsaCallAuthenticationPackage(
                                    _lsaHandle,
                                    _packageNumber,
                                    requestAlloc,
                                    (uint)sizeofRequest,
                                    ref nullPtr,
                                    out var dwReturnCode,
                                    out var ntSubStatus);

                if (FAILED(ntStatus))
                {
                    throw new Win32Exception(ntStatus, $"{nameof(Native.LsaCallAuthenticationPackage)} has failed");
                }

                if (FAILED((int)ntSubStatus))
                {
                    if (ntSubStatus == Native.NtSubStatus.STATUS_PRIVILEGE_NOT_HELD)
                    {
                        throw new Win32Exception((unchecked((int)ntSubStatus)), "**** The TCB privilege is required to perform this operation.\n(hint: launch the command with PsExec from Sysinternals with admin rights: psexec.exe -s SslCacheNet.exe -p)");
                    }
                    else
                    {
                        throw new Win32Exception((unchecked((int)ntSubStatus)), string.Format($"**** Error {ntSubStatus} occurred while purging cache entries.", ntSubStatus));
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