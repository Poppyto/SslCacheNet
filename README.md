# SslCacheNet

Utility to list and purge client & server secure connection cache from SCHANNEL (lsass.exe)

## Usage

SslCacheNet [operation] [flags]

  Operations:

    -?     Show usage
    -l     List cache entries (default)
    -i     List cache entries interactively
    -p     Purge cache entries

  flags:

    -c      Include all client entries (default)
    -s      Include all server entries

## Examples

* Show client & server SSL/TLS connection cache

      SslCacheNet -l -c -s

* Show interactive client & server SSL/TLS connection cache with a 500ms refreshing time

      SslCacheNet -i500 -c -s

* Purge client & server SSL/TLS connection cache

      # 1. Prompt in Admin
      # 2. Use PsExec from Sysinternals to permit SeTcbPrivilege to work
* 
      PsExec.exe -s SslCacheNet.exe -p -c -s