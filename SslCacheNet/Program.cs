using System;
using System.Linq;
using System.Threading;

namespace SslCacheNet
{
    public partial class Program
    {
        static readonly char[] Separators = new char[] { '/', '-' };
        const int DefaultInteractiveTimeout = 2000;

        static void DisplayAppUsage()
        {
            Console.WriteLine("USAGE: SslCacheNet [operation] [flags]");
            Console.WriteLine();
            Console.WriteLine("  Operations:");
            Console.WriteLine("    -?     Show usage");
            Console.WriteLine("    -l     List cache entries (default)");
            Console.WriteLine("    -i     List cache entries interactively");
            Console.WriteLine("    -p     Purge cache entries");
            Console.WriteLine();
            Console.WriteLine("  flags:");
            Console.WriteLine("    -c      Include all client entries (default)");
            Console.WriteLine("    -s      Include all server entries");
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("SslCacheNet");

            Operations dwOperation = Operations.ListCacheEntries;

            bool includeClient = false;
            bool includeServer = false;
            int interactiveMilliseconds = DefaultInteractiveTimeout;

            ExtractArguments(args,
                             ref dwOperation,
                             ref includeClient,
                             ref includeServer,
                             ref interactiveMilliseconds
                             );

            using (var lsa = new LSA())
            {
                LaunchOperation(lsa, dwOperation, includeClient, includeServer, interactiveMilliseconds);
            }
        }

        private static void LaunchOperation(LSA lsa, Operations dwOperation, bool includeClient, bool includeServer, int interactiveMilliseconds)
        {
            try
            {
                switch (dwOperation)
                {
                    case Operations.ShowUsage:
                        {
                            DisplayAppUsage();
                        }
                        break;
                    case Operations.ListCacheEntries:
                        {
                            DisplayCacheInfos(lsa, includeClient, includeServer);
                        }
                        break;
                    case Operations.ListEntriesInteractive:
                        {
                            DisplayCacheInfoInteractive(lsa, includeClient, includeServer, interactiveMilliseconds);
                        }
                        break;
                    case Operations.PurgeCacheEntries:
                        {
                            PurgeCacheEntries(lsa, includeClient, includeServer);
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("{0}", ex.Message);
            }
        }

        private static void DisplayCacheInfos(LSA lsa, bool includeClient, bool includeServer)
        {
            Console.WriteLine();
            Console.WriteLine("DISPLAY CACHE ENTRIES");
            Console.WriteLine();

            if (includeClient)
            {
                Console.WriteLine("-- CLIENT --");
                DisplayCacheInfo(lsa.GetSessionCacheInfo(true, false));
            }

            if (includeServer)
            {
                Console.WriteLine("-- SERVER --");
                DisplayCacheInfo(lsa.GetSessionCacheInfo(false, true));
            }

            if (includeClient && includeServer)
            {
                Console.WriteLine("-- TOTAL --");
                DisplayCacheInfo(lsa.GetSessionCacheInfo(true, true));
            }
        }

        private static void ExtractArguments(string[] args, ref Operations dwOperation, ref bool includeClient, ref bool includeServer, ref int interactiveMilliseconds)
        {
            foreach (var argv in args)
            {
                if (!Separators.Contains(argv[0]))
                {
                    Console.WriteLine(string.Format($"**** Invalid argument \"{argv}\""));
                    DisplayAppUsage();
                    return;
                }

                if (argv.Length <= 1)
                {
                    DisplayAppUsage();
                    return;
                }

                var operatorOrFlag = argv[1];
                var option = argv.Substring(2);

                switch (operatorOrFlag)
                {
                    case '?':
                        dwOperation = Operations.ShowUsage;
                        return;

                    case 'l':
                        dwOperation = Operations.ListCacheEntries;
                        break;

                    case 'i':
                        dwOperation = Operations.ListEntriesInteractive;

                        if (option.Length > 0)
                        {
                            Int32.TryParse(option, out interactiveMilliseconds);
                        }

                        if (interactiveMilliseconds <= 0)
                        {
                            interactiveMilliseconds = DefaultInteractiveTimeout;
                        }
                        break;

                    case 'p':
                        dwOperation = Operations.PurgeCacheEntries;
                        break;

                    case 'c':
                        includeClient = true;
                        break;

                    case 's':
                        includeServer = true;
                        break;

                    default:
                        Console.WriteLine($"**** Invalid option \"{argv}\"");
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


        static void DisplayCacheInfoInteractive(LSA lsa, bool includeClient, bool includeServer, int milliseconds)
        {
            Console.Clear();

            while (true)
            {
                Console.SetCursorPosition(0, 0);

                DisplayCacheInfos(lsa, includeClient, includeServer);

                Thread.Sleep(milliseconds);
            }
        }

        static void PurgeCacheEntries(LSA lsa, bool includeClient, bool includeServer)
        {
            Console.WriteLine("PURGE CACHE ENTRIES");
            Console.WriteLine("Client:{0}", includeClient ? "yes" : "no");
            Console.WriteLine("Server:{0}", includeServer ? "yes" : "no");

            lsa.PurgeCacheEntries(includeClient, includeServer);
        }
    }
}