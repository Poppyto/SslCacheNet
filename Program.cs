using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace SslCacheNet
{
    public class Program
    {
        static readonly char[] Separators = new char[] { '/', '-' };

        enum Operations
        {
            Unknown,
            ListCacheEntries = 1,
            ListEntriesInteractive = 2,
            PurgeCacheEntries = 3,
        }

        static void DisplayAppUsage()
        {
            Console.WriteLine("USAGE: SslCacheNet [ operation ] [ flags ]");
            Console.WriteLine();
            Console.WriteLine("    OPERATIONS:");
            Console.WriteLine("        -l      List cache entries (default)");
            Console.WriteLine("        -i      List cache entries interactively");
            Console.WriteLine("        -p      Purge cache entries");
            Console.WriteLine();
            Console.WriteLine("    FLAGS:");
            Console.WriteLine("        -c      Include client entries (default)");
            Console.WriteLine("        -s      Include server entries");
            Console.WriteLine("        -S      Include IIS mapped server entries (purge only)");
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("SslCacheNet");

            Operations dwOperation = Operations.ListCacheEntries;

            bool includeClient = false;
            bool includeServer = false;
            bool fIncludeMappedEntries = false;
            string pszServerName = null;

            //Thread.Sleep(10 * 1000);
            //Debugger.Launch();

            ExtractArguments(args,
                             ref dwOperation,
                             ref includeClient,
                             ref includeServer,
                             ref fIncludeMappedEntries,
                             ref pszServerName);

            using (var lsa = new LSA())
            {
                LaunchOperation(lsa, dwOperation, includeClient, includeServer, fIncludeMappedEntries, pszServerName);
            }
        }

        private static void LaunchOperation(LSA lsa, Operations dwOperation, bool includeClient, bool includeServer, bool fIncludeMappedEntries, string pszServerName)
        {
            switch (dwOperation)
            {
                case Operations.ListCacheEntries:
                    {
                        DisplayCacheInfos(lsa, includeClient, includeServer);
                    }
                    break;
                case Operations.ListEntriesInteractive:
                    {
                        DisplayCacheInfoInteractive(lsa, includeClient, includeServer);
                    }
                    break;
                case Operations.PurgeCacheEntries:
                    {
                        PurgeCacheEntries(lsa, includeClient, includeServer, fIncludeMappedEntries, pszServerName);
                    }
                    break;
            }
        }

        private static void DisplayCacheInfos(LSA lsa, bool includeClient, bool includeServer)
        {
            Console.WriteLine();
            Console.WriteLine("DISPLAY CACHE ENTRIES");
            Console.WriteLine();

            if (includeClient)
            {
                Console.WriteLine("--CLIENT--");
                DisplayCacheInfo(lsa.GetSessionCacheInfo(true, false));
            }

            if (includeServer)
            {
                Console.WriteLine("--SERVER--");
                DisplayCacheInfo(lsa.GetSessionCacheInfo(false, true));
            }

            if (includeClient && includeServer)
            {
                Console.WriteLine("--TOTAL--");
                DisplayCacheInfo(lsa.GetSessionCacheInfo(true, true));
            }
        }

        private static void ExtractArguments(string[] args, ref Operations dwOperation, ref bool includeClient, ref bool includeServer, ref bool fIncludeMappedEntries, ref string pszServerName)
        {
            foreach (var argv in args)
            {
                if (!Separators.Contains(argv[0]))
                {
                    Console.WriteLine(string.Format($"**** Invalid argument \"{argv}\"\n"));
                    DisplayAppUsage();
                    return;
                }

                var iOption = argv[1];
                var pszOption = argv.Substring(2);

                switch (iOption)
                {
                    case 'l':
                        dwOperation = Operations.ListCacheEntries;
                        break;

                    case 'i':
                        dwOperation = Operations.ListEntriesInteractive;
                        break;

                    case 'p':
                        dwOperation = Operations.PurgeCacheEntries;
                        break;

                    case 'c':
                        includeClient = true;
                        break;

                    case 's':
                        if (pszOption.Length == 0)
                        {
                            includeServer = true;
                        }
                        else
                        {
                            pszServerName = pszOption;
                            includeServer = true;
                        }
                        break;

                    case 'S':
                        fIncludeMappedEntries = true;
                        includeServer = true;
                        break;

                    default:
                        Console.WriteLine($"**** Invalid option \"{argv}\"\n");
                        DisplayAppUsage();
                        return;
                }
            }

            if (!includeClient && !includeServer)
            {
                if (dwOperation == Operations.PurgeCacheEntries)
                {
                    includeClient = true;
                }
                else
                {
                    includeClient = true;
                    includeServer = true;
                }
            }

        }

        static void DisplayCacheInfo(Native.SSL_SESSION_CACHE_INFO_RESPONSE sslSessionCacheInfo)
        {
            Console.WriteLine("CacheSize:      {0}", sslSessionCacheInfo.CacheSize);
            Console.WriteLine("Entries:        {0}", sslSessionCacheInfo.Entries);
            Console.WriteLine("ActiveEntries:  {0}", sslSessionCacheInfo.ActiveEntries);
            Console.WriteLine("Zombies:        {0}", sslSessionCacheInfo.Zombies);
            Console.WriteLine("ExpiredZombies: {0}", sslSessionCacheInfo.ExpiredZombies);
            Console.WriteLine("AbortedZombies: {0}", sslSessionCacheInfo.AbortedZombies);
            Console.WriteLine("DeletedZombies: {0}", sslSessionCacheInfo.DeletedZombies);
        }


        static void DisplayCacheInfoInteractive(LSA lsa, bool includeClient, bool includeServer)
        {

            Console.Clear();

            while (true)
            {
                Console.SetCursorPosition(0, 0);

                DisplayCacheInfos(lsa, includeClient, includeServer);

                Thread.Sleep(2000);
            }
        }

        static void PurgeCacheEntries(LSA lsa, bool includeClient, bool includeServer, bool includeMappedEntries, string pszServerName)
        {
            lsa.PurgeCacheEntries(includeClient, includeServer, includeMappedEntries, pszServerName);
        }
    }
}