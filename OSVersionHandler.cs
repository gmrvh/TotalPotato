namespace TotalPotato
{
    public static class OSVersionHandler
    {
        public static Version GetOSVersion()
        {
            return Environment.OSVersion.Version;

        }
        public static string GetVersion()
        {
            Version v = GetOSVersion();
            return $"Windows {v.Major}.{v.Minor}.{v.Build}";
        }

        public static bool IsBetweenBuilds(int minBuild, int maxBuild)
        {
            int currentBuild = Environment.OSVersion.Version.Build;
            Console.WriteLine("[+] Current OS Build |\t{0}", currentBuild);
            return currentBuild >= minBuild && currentBuild <= maxBuild;
        }
    }
}
