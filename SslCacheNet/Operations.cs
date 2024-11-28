namespace SslCacheNet
{
    public partial class Program
    {
        enum Operations
        {
            Unknown,
            ShowUsage = 1,
            ListCacheEntries = 2,
            ListEntriesInteractive = 3,
            PurgeCacheEntries = 4,
        }
    }
}