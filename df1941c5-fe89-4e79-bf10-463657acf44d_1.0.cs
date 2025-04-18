



namespace rpc_df1941c5_fe89_4e79_bf10_463657acf44d_1_0
{

    #region Marshal Helpers
    internal class _Marshal_Helper : NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer
    {
        public void Write_0(Struct_0 p0)
        {
            WriteStruct<Struct_0>(p0);
        }
        public void Write_1(Struct_1 p0)
        {
            WriteStruct<Struct_1>(p0);
        }
        public void Write_2(Struct_2 p0)
        {
            WriteStruct<Struct_2>(p0);
        }
        public void Write_3(Struct_3 p0)
        {
            WriteStruct<Struct_3>(p0);
        }
        public void Write_4(Struct_4 p0)
        {
            WriteStruct<Struct_4>(p0);
        }
        public void Write_5(Struct_5 p0)
        {
            WriteStruct<Struct_5>(p0);
        }
        public void Write_6(Struct_6 p0)
        {
            WriteStruct<Struct_6>(p0);
        }
        public void Write_7(Struct_7 p0)
        {
            WriteStruct<Struct_7>(p0);
        }
        public void Write_8(Struct_8 p0)
        {
            WriteStruct<Struct_8>(p0);
        }
        public void Write_9(Struct_9 p0)
        {
            WriteStruct<Struct_9>(p0);
        }
        public void Write_10(Struct_10 p0)
        {
            WriteStruct<Struct_10>(p0);
        }
        public void Write_11(Struct_11 p0)
        {
            WriteStruct<Struct_11>(p0);
        }
        public void Write_12(Struct_12 p0)
        {
            WriteStruct<Struct_12>(p0);
        }
        public void Write_13(Struct_13 p0)
        {
            WriteStruct<Struct_13>(p0);
        }
        public void Write_14(Struct_14 p0)
        {
            WriteStruct<Struct_14>(p0);
        }
        public void Write_15(Struct_15 p0)
        {
            WriteStruct<Struct_15>(p0);
        }
        public void Write_16(Struct_16 p0)
        {
            WriteStruct<Struct_16>(p0);
        }
        public void Write_17(Struct_1[] p0, long p1)
        {
            WriteConformantStructArray<Struct_1>(p0, p1);
        }
        public void Write_18(int[] p0, long p1)
        {
            WriteConformantArray<int>(p0, p1);
        }
        public void Write_19(sbyte[] p0)
        {
            WriteFixedPrimitiveArray<sbyte>(p0, 6);
        }
        public void Write_20(sbyte[] p0, long p1)
        {
            WriteConformantArray<sbyte>(p0, p1);
        }
        public void Write_21(Struct_6[] p0, long p1)
        {
            WriteConformantStructArray<Struct_6>(p0, p1);
        }
        public void Write_22(sbyte[] p0, long p1)
        {
            WriteConformantArray<sbyte>(p0, p1);
        }
        public void Write_23(sbyte[] p0, long p1)
        {
            WriteConformantArray<sbyte>(p0, p1);
        }
        public void Write_24(sbyte[] p0, long p1)
        {
            WriteConformantArray<sbyte>(p0, p1);
        }
        public void Write_25(Struct_12[] p0, long p1)
        {
            WriteConformantStructArray<Struct_12>(p0, p1);
        }
        public void Write_26(sbyte[] p0)
        {
            WriteFixedPrimitiveArray<sbyte>(p0, 16);
        }
        public void Write_27(Struct_15[] p0, long p1)
        {
            WriteConformantStructArray<Struct_15>(p0, p1);
        }
        public void Write_28(System.Guid[] p0, long p1)
        {
            WriteConformantArrayCallback<System.Guid>(p0, new System.Action<System.Guid>(this.WriteGuid), p1);
        }
        public void Write_29(long[] p0, long p1)
        {
            WriteConformantArray<long>(p0, p1);
        }
        public void Write_30(NtApiDotNet.Ndr.Marshal.NdrPipe<sbyte> p0)
        {
            WritePipe<sbyte>(p0);
        }
        public void Write_31(NtApiDotNet.Ndr.Marshal.NdrPipe<sbyte> p0)
        {
            WritePipe<sbyte>(p0);
        }
        public void Write_32(NtApiDotNet.Ndr.Marshal.NdrPipe<sbyte> p0)
        {
            WritePipe<sbyte>(p0);
        }
        public void Write_33(sbyte[] p0, long p1)
        {
            WriteConformantArray<sbyte>(p0, p1);
        }
        public void Write_34(sbyte[] p0, long p1)
        {
            WriteConformantArray<sbyte>(p0, p1);
        }
        public void Write_35(sbyte[] p0, long p1)
        {
            WriteConformantArray<sbyte>(p0, p1);
        }
        public void Write_36(sbyte[] p0, long p1)
        {
            WriteConformantArray<sbyte>(p0, p1);
        }
        public void Write_37(sbyte[] p0, long p1)
        {
            WriteConformantArray<sbyte>(p0, p1);
        }
        public void Write_38(sbyte[] p0, long p1)
        {
            WriteConformantArray<sbyte>(p0, p1);
        }
    }
    internal class _Unmarshal_Helper : NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer
    {
        public _Unmarshal_Helper(NtApiDotNet.Win32.Rpc.RpcClientResponse r) :
                base(r.NdrBuffer, r.Handles, r.DataRepresentation)
        {
        }
        public _Unmarshal_Helper(byte[] ba) :
                base(ba)
        {
        }
        public Struct_0 Read_0()
        {
            return ReadStruct<Struct_0>();
        }
        public Struct_1 Read_1()
        {
            return ReadStruct<Struct_1>();
        }
        public Struct_2 Read_2()
        {
            return ReadStruct<Struct_2>();
        }
        public Struct_3 Read_3()
        {
            return ReadStruct<Struct_3>();
        }
        public Struct_4 Read_4()
        {
            return ReadStruct<Struct_4>();
        }
        public Struct_5 Read_5()
        {
            return ReadStruct<Struct_5>();
        }
        public Struct_6 Read_6()
        {
            return ReadStruct<Struct_6>();
        }
        public Struct_7 Read_7()
        {
            return ReadStruct<Struct_7>();
        }
        public Struct_8 Read_8()
        {
            return ReadStruct<Struct_8>();
        }
        public Struct_9 Read_9()
        {
            return ReadStruct<Struct_9>();
        }
        public Struct_10 Read_10()
        {
            return ReadStruct<Struct_10>();
        }
        public Struct_11 Read_11()
        {
            return ReadStruct<Struct_11>();
        }
        public Struct_12 Read_12()
        {
            return ReadStruct<Struct_12>();
        }
        public Struct_13 Read_13()
        {
            return ReadStruct<Struct_13>();
        }
        public Struct_14 Read_14()
        {
            return ReadStruct<Struct_14>();
        }
        public Struct_15 Read_15()
        {
            return ReadStruct<Struct_15>();
        }
        public Struct_16 Read_16()
        {
            return ReadStruct<Struct_16>();
        }
        public Struct_1[] Read_17()
        {
            return ReadConformantStructArray<Struct_1>();
        }
        public int[] Read_18()
        {
            return ReadConformantArray<int>();
        }
        public sbyte[] Read_19()
        {
            return ReadFixedPrimitiveArray<sbyte>(6);
        }
        public sbyte[] Read_20()
        {
            return ReadConformantArray<sbyte>();
        }
        public Struct_6[] Read_21()
        {
            return ReadConformantStructArray<Struct_6>();
        }
        public sbyte[] Read_22()
        {
            return ReadConformantArray<sbyte>();
        }
        public sbyte[] Read_23()
        {
            return ReadConformantArray<sbyte>();
        }
        public sbyte[] Read_24()
        {
            return ReadConformantArray<sbyte>();
        }
        public Struct_12[] Read_25()
        {
            return ReadConformantStructArray<Struct_12>();
        }
        public sbyte[] Read_26()
        {
            return ReadFixedPrimitiveArray<sbyte>(16);
        }
        public Struct_15[] Read_27()
        {
            return ReadConformantStructArray<Struct_15>();
        }
        public System.Guid[] Read_28()
        {
            return ReadConformantArrayCallback<System.Guid>(new System.Func<System.Guid>(this.ReadGuid));
        }
        public long[] Read_29()
        {
            return ReadConformantArray<long>();
        }
        public NtApiDotNet.Ndr.Marshal.NdrPipe<sbyte> Read_30()
        {
            return ReadPipe<sbyte>();
        }
        public NtApiDotNet.Ndr.Marshal.NdrPipe<sbyte> Read_31()
        {
            return ReadPipe<sbyte>();
        }
        public NtApiDotNet.Ndr.Marshal.NdrPipe<sbyte> Read_32()
        {
            return ReadPipe<sbyte>();
        }
        public sbyte[] Read_33()
        {
            return ReadConformantArray<sbyte>();
        }
        public sbyte[] Read_34()
        {
            return ReadConformantArray<sbyte>();
        }
        public sbyte[] Read_35()
        {
            return ReadConformantArray<sbyte>();
        }
        public sbyte[] Read_36()
        {
            return ReadConformantArray<sbyte>();
        }
        public sbyte[] Read_37()
        {
            return ReadConformantArray<sbyte>();
        }
        public sbyte[] Read_38()
        {
            return ReadConformantArray<sbyte>();
        }
    }
    #endregion
    #region Complex Types
    public struct Struct_0 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteEmbeddedPointer<Struct_1[], long>(Member8, new System.Action<Struct_1[], long>(m.Write_17), Member0);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<Struct_1[]>(new System.Func<Struct_1[]>(u.Read_17), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_1[]> Member8;
        public static Struct_0 CreateDefault()
        {
            return new Struct_0();
        }
        public Struct_0(int Member0, Struct_1[] Member8)
        {
            this.Member0 = Member0;
            this.Member8 = Member8;
        }
    }
    public struct Struct_1 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteEmbeddedPointer<Struct_2>(Member8, new System.Action<Struct_2>(m.Write_2));
            m.WriteEmbeddedPointer<Struct_4>(Member10, new System.Action<Struct_4>(m.Write_4));
            m.WriteEmbeddedPointer<string>(Member18, new System.Action<string>(m.WriteTerminatedString));
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<Struct_2>(new System.Func<Struct_2>(u.Read_2), false);
            Member10 = u.ReadEmbeddedPointer<Struct_4>(new System.Func<Struct_4>(u.Read_4), false);
            Member18 = u.ReadEmbeddedPointer<string>(new System.Func<string>(u.ReadConformantVaryingString), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_2> Member8;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_4> Member10;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<string> Member18;
        public static Struct_1 CreateDefault()
        {
            return new Struct_1();
        }
        public Struct_1(int Member0, System.Nullable<Struct_2> Member8, System.Nullable<Struct_4> Member10, string Member18)
        {
            this.Member0 = Member0;
            this.Member8 = Member8;
            this.Member10 = Member10;
            this.Member18 = Member18;
        }
    }
    public struct Struct_2 : NtApiDotNet.Ndr.Marshal.INdrConformantStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteSByte(Member0);
            m.WriteSByte(Member1);
            m.Write_3(Member2);
            m.Write_18(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(Member8, "Member8"), Member1);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadSByte();
            Member1 = u.ReadSByte();
            Member2 = u.Read_3();
            Member8 = u.Read_18();
        }
        int NtApiDotNet.Ndr.Marshal.INdrConformantStructure.GetConformantDimensions()
        {
            return 1;
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public sbyte Member0;
        public sbyte Member1;
        public Struct_3 Member2;
        public int[] Member8;
        public static Struct_2 CreateDefault()
        {
            Struct_2 ret = new Struct_2();
            ret.Member8 = new int[0];
            return ret;
        }
        public Struct_2(sbyte Member0, sbyte Member1, Struct_3 Member2, int[] Member8)
        {
            this.Member0 = Member0;
            this.Member1 = Member1;
            this.Member2 = Member2;
            this.Member8 = Member8;
        }
    }
    public struct Struct_3 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.Write_19(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(Member0, "Member0"));
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.Read_19();
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 1;
        }
        public sbyte[] Member0;
        public static Struct_3 CreateDefault()
        {
            Struct_3 ret = new Struct_3();
            ret.Member0 = new sbyte[6];
            return ret;
        }
        public Struct_3(sbyte[] Member0)
        {
            this.Member0 = Member0;
        }
    }
    public struct Struct_4 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteEmbeddedPointer<sbyte[], long>(Member8, new System.Action<sbyte[], long>(m.Write_20), Member0);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<sbyte[]>(new System.Func<sbyte[]>(u.Read_20), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<sbyte[]> Member8;
        public static Struct_4 CreateDefault()
        {
            return new Struct_4();
        }
        public Struct_4(int Member0, sbyte[] Member8)
        {
            this.Member0 = Member0;
            this.Member8 = Member8;
        }
    }
    public struct Struct_5 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteEmbeddedPointer<Struct_6[], long>(Member8, new System.Action<Struct_6[], long>(m.Write_21), Member0);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<Struct_6[]>(new System.Func<Struct_6[]>(u.Read_21), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_6[]> Member8;
        public static Struct_5 CreateDefault()
        {
            return new Struct_5();
        }
        public Struct_5(int Member0, Struct_6[] Member8)
        {
            this.Member0 = Member0;
            this.Member8 = Member8;
        }
    }
    public struct Struct_6 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteEmbeddedPointer<Struct_2>(Member8, new System.Action<Struct_2>(m.Write_2));
            m.WriteEmbeddedPointer<Struct_7>(Member10, new System.Action<Struct_7>(m.Write_7));
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<Struct_2>(new System.Func<Struct_2>(u.Read_2), false);
            Member10 = u.ReadEmbeddedPointer<Struct_7>(new System.Func<Struct_7>(u.Read_7), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_2> Member8;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_7> Member10;
        public static Struct_6 CreateDefault()
        {
            return new Struct_6();
        }
        public Struct_6(int Member0, System.Nullable<Struct_2> Member8, System.Nullable<Struct_7> Member10)
        {
            this.Member0 = Member0;
            this.Member8 = Member8;
            this.Member10 = Member10;
        }
    }
    public struct Struct_7 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteInt32(Member4);
            m.WriteEmbeddedPointer<sbyte[], long>(Member8, new System.Action<sbyte[], long>(m.Write_22), Member4);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member4 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<sbyte[]>(new System.Func<sbyte[]>(u.Read_22), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public int Member4;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<sbyte[]> Member8;
        public static Struct_7 CreateDefault()
        {
            return new Struct_7();
        }
        public Struct_7(int Member0, int Member4, sbyte[] Member8)
        {
            this.Member0 = Member0;
            this.Member4 = Member4;
            this.Member8 = Member8;
        }
    }
    public struct Struct_8 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteEmbeddedPointer<sbyte[], long>(Member8, new System.Action<sbyte[], long>(m.Write_23), Member0);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<sbyte[]>(new System.Func<sbyte[]>(u.Read_23), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<sbyte[]> Member8;
        public static Struct_8 CreateDefault()
        {
            return new Struct_8();
        }
        public Struct_8(int Member0, sbyte[] Member8)
        {
            this.Member0 = Member0;
            this.Member8 = Member8;
        }
    }
    public struct Struct_9 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteInt32(Member4);
            m.WriteEmbeddedPointer<sbyte[], long>(Member8, new System.Action<sbyte[], long>(m.Write_24), NtApiDotNet.Win32.Rpc.RpcUtils.OpPlus(Member4, Member0));
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member4 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<sbyte[]>(new System.Func<sbyte[]>(u.Read_24), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public int Member4;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<sbyte[]> Member8;
        public static Struct_9 CreateDefault()
        {
            return new Struct_9();
        }
        public Struct_9(int Member0, int Member4, sbyte[] Member8)
        {
            this.Member0 = Member0;
            this.Member4 = Member4;
            this.Member8 = Member8;
        }
    }
    public struct Struct_10 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteEmbeddedPointer<Struct_0>(Member8, new System.Action<Struct_0>(m.Write_0));
            m.WriteEmbeddedPointer<Struct_6>(Member10, new System.Action<Struct_6>(m.Write_6));
            m.WriteEmbeddedPointer<Struct_8>(Member18, new System.Action<Struct_8>(m.Write_8));
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<Struct_0>(new System.Func<Struct_0>(u.Read_0), false);
            Member10 = u.ReadEmbeddedPointer<Struct_6>(new System.Func<Struct_6>(u.Read_6), false);
            Member18 = u.ReadEmbeddedPointer<Struct_8>(new System.Func<Struct_8>(u.Read_8), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_0> Member8;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_6> Member10;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_8> Member18;
        public static Struct_10 CreateDefault()
        {
            return new Struct_10();
        }
        public Struct_10(int Member0, System.Nullable<Struct_0> Member8, System.Nullable<Struct_6> Member10, System.Nullable<Struct_8> Member18)
        {
            this.Member0 = Member0;
            this.Member8 = Member8;
            this.Member10 = Member10;
            this.Member18 = Member18;
        }
    }
    public struct Struct_11 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteEmbeddedPointer<Struct_12[], long>(Member8, new System.Action<Struct_12[], long>(m.Write_25), Member0);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<Struct_12[]>(new System.Func<Struct_12[]>(u.Read_25), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_12[]> Member8;
        public static Struct_11 CreateDefault()
        {
            return new Struct_11();
        }
        public Struct_11(int Member0, Struct_12[] Member8)
        {
            this.Member0 = Member0;
            this.Member8 = Member8;
        }
    }
    public struct Struct_12 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteEmbeddedPointer<Struct_2>(Member8, new System.Action<Struct_2>(m.Write_2));
            m.WriteEmbeddedPointer<string>(Member10, new System.Action<string>(m.WriteTerminatedString));
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<Struct_2>(new System.Func<Struct_2>(u.Read_2), false);
            Member10 = u.ReadEmbeddedPointer<string>(new System.Func<string>(u.ReadConformantVaryingString), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_2> Member8;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<string> Member10;
        public static Struct_12 CreateDefault()
        {
            return new Struct_12();
        }
        public Struct_12(int Member0, System.Nullable<Struct_2> Member8, string Member10)
        {
            this.Member0 = Member0;
            this.Member8 = Member8;
            this.Member10 = Member10;
        }
    }
    public struct Struct_13 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.Write_26(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(Member0, "Member0"));
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.Read_26();
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 1;
        }
        public sbyte[] Member0;
        public static Struct_13 CreateDefault()
        {
            Struct_13 ret = new Struct_13();
            ret.Member0 = new sbyte[16];
            return ret;
        }
        public Struct_13(sbyte[] Member0)
        {
            this.Member0 = Member0;
        }
    }
    public struct Struct_14 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteEmbeddedPointer<Struct_15[], long>(Member8, new System.Action<Struct_15[], long>(m.Write_27), Member0);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<Struct_15[]>(new System.Func<Struct_15[]>(u.Read_27), false);
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<Struct_15[]> Member8;
        public static Struct_14 CreateDefault()
        {
            return new Struct_14();
        }
        public Struct_14(int Member0, Struct_15[] Member8)
        {
            this.Member0 = Member0;
            this.Member8 = Member8;
        }
    }
    public struct Struct_15 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteEmbeddedPointer<System.Guid[], long>(Member8, new System.Action<System.Guid[], long>(m.Write_28), Member0);
            m.WriteInt32(Member10);
            m.WriteEmbeddedPointer<long[], long>(Member18, new System.Action<long[], long>(m.Write_29), Member10);
            m.WriteEmbeddedPointer<string>(Member20, new System.Action<string>(m.WriteTerminatedString));
            m.Write_16(Member28);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member8 = u.ReadEmbeddedPointer<System.Guid[]>(new System.Func<System.Guid[]>(u.Read_28), false);
            Member10 = u.ReadInt32();
            Member18 = u.ReadEmbeddedPointer<long[]>(new System.Func<long[]>(u.Read_29), false);
            Member20 = u.ReadEmbeddedPointer<string>(new System.Func<string>(u.ReadConformantVaryingString), false);
            Member28 = u.Read_16();
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<System.Guid[]> Member8;
        public int Member10;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<long[]> Member18;
        public NtApiDotNet.Ndr.Marshal.NdrEmbeddedPointer<string> Member20;
        public Struct_16 Member28;
        public static Struct_15 CreateDefault()
        {
            return new Struct_15();
        }
        public Struct_15(int Member0, System.Guid[] Member8, int Member10, long[] Member18, string Member20, Struct_16 Member28)
        {
            this.Member0 = Member0;
            this.Member8 = Member8;
            this.Member10 = Member10;
            this.Member18 = Member18;
            this.Member20 = Member20;
            this.Member28 = Member28;
        }
    }
    public struct Struct_16 : NtApiDotNet.Ndr.Marshal.INdrStructure
    {
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Marshal(NtApiDotNet.Ndr.Marshal.NdrMarshalBuffer m)
        {
            Marshal(((_Marshal_Helper)(m)));
        }
        private void Marshal(_Marshal_Helper m)
        {
            m.WriteInt32(Member0);
            m.WriteInt32(Member4);
        }
        void NtApiDotNet.Ndr.Marshal.INdrStructure.Unmarshal(NtApiDotNet.Ndr.Marshal.NdrUnmarshalBuffer u)
        {
            Unmarshal(((_Unmarshal_Helper)(u)));
        }
        private void Unmarshal(_Unmarshal_Helper u)
        {
            Member0 = u.ReadInt32();
            Member4 = u.ReadInt32();
        }
        int NtApiDotNet.Ndr.Marshal.INdrStructure.GetAlignment()
        {
            return 4;
        }
        public int Member0;
        public int Member4;
        public static Struct_16 CreateDefault()
        {
            return new Struct_16();
        }
        public Struct_16(int Member0, int Member4)
        {
            this.Member0 = Member0;
            this.Member4 = Member4;
        }
    }
    #endregion
    #region Client Implementation
    public sealed class Client : NtApiDotNet.Win32.Rpc.RpcClientBase
    {
        public Client() :
                base("df1941c5-fe89-4e79-bf10-463657acf44d", 1, 0)
        {
        }
        private _Unmarshal_Helper SendReceive(int p, _Marshal_Helper m)
        {
            return new _Unmarshal_Helper(SendReceive(p, m.DataRepresentation, m.ToArray(), m.Handles));
        }
        public int EfsRpcOpenFileRaw(out NtApiDotNet.Ndr.Marshal.NdrContextHandle p0, string p1, int p2)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p1, "p1"));
            m.WriteInt32(p2);
            _Unmarshal_Helper u = SendReceive(0, m);
            p0 = u.ReadContextHandle();
            return u.ReadInt32();
        }
        public int EfsRpcReadFileRaw(NtApiDotNet.Ndr.Marshal.NdrContextHandle p0, out NtApiDotNet.Ndr.Marshal.NdrPipe<sbyte> p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteContextHandle(p0);
            _Unmarshal_Helper u = SendReceive(1, m);
            p1 = u.Read_30();
            return u.ReadInt32();
        }
        public int EfsRpcWriteFileRaw(NtApiDotNet.Ndr.Marshal.NdrContextHandle p0, NtApiDotNet.Ndr.Marshal.NdrPipe<sbyte> p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteContextHandle(p0);
            m.Write_31(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p1, "p1"));
            _Unmarshal_Helper u = SendReceive(2, m);
            return u.ReadInt32();
        }
        public void EfsRpcCloseRaw(ref NtApiDotNet.Ndr.Marshal.NdrContextHandle p0)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteContextHandle(p0);
            _Unmarshal_Helper u = SendReceive(3, m);
            p0 = u.ReadContextHandle();
        }
        public int EfsRpcEncryptFileSrv(string p0)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            _Unmarshal_Helper u = SendReceive(4, m);
            return u.ReadInt32();
        }
        public int EfsRpcDecryptFileSrv(string p0, int p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.WriteInt32(p1);
            _Unmarshal_Helper u = SendReceive(5, m);
            return u.ReadInt32();
        }
        public int EfsRpcQueryUsersOnFile(string p0, out System.Nullable<Struct_0> p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            _Unmarshal_Helper u = SendReceive(6, m);
            p1 = u.ReadReferentValue<Struct_0>(new System.Func<Struct_0>(u.Read_0), false);
            return u.ReadInt32();
        }
        public int EfsRpcQueryRecoveryAgents(string p0, out System.Nullable<Struct_0> p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            _Unmarshal_Helper u = SendReceive(7, m);
            p1 = u.ReadReferentValue<Struct_0>(new System.Func<Struct_0>(u.Read_0), false);
            return u.ReadInt32();
        }
        public int EfsRpcRemoveUsersFromFile(string p0, Struct_0 p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.Write_0(p1);
            _Unmarshal_Helper u = SendReceive(8, m);
            return u.ReadInt32();
        }
        public int EfsRpcAddUsersToFile(string p0, Struct_5 p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.Write_5(p1);
            _Unmarshal_Helper u = SendReceive(9, m);
            return u.ReadInt32();
        }
        public int EfsRpcSetFileEncryptionKey(System.Nullable<Struct_6> p0, int p1, int p2)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<Struct_6>(m.Write_6));
            m.WriteInt32(p1);
            m.WriteInt32(p2);
            _Unmarshal_Helper u = SendReceive(10, m);
            return u.ReadInt32();
        }
        public int EfsRpcFileKeyInfoEx(string p0, string p1, int p2, int p3, System.Nullable<Struct_8> p4, int p5)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p1, "p1"));
            m.WriteInt32(p2);
            m.WriteInt32(p3);
            m.WriteReferent(p4, new System.Action<Struct_8>(m.Write_8));
            m.WriteInt32(p5);
            _Unmarshal_Helper u = SendReceive(11, m);
            return u.ReadInt32();
        }
        public int EfsRpcFileKeyInfo(string p0, int p1, out System.Nullable<Struct_8> p2)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.WriteInt32(p1);
            _Unmarshal_Helper u = SendReceive(12, m);
            p2 = u.ReadReferentValue<Struct_8>(new System.Func<Struct_8>(u.Read_8), false);
            return u.ReadInt32();
        }
        public int EfsRpcDuplicateEncryptionInfoFile(string p0, string p1, int p2, int p3, System.Nullable<Struct_8> p4, int p5)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p1, "p1"));
            m.WriteInt32(p2);
            m.WriteInt32(p3);
            m.WriteReferent(p4, new System.Action<Struct_8>(m.Write_8));
            m.WriteInt32(p5);
            _Unmarshal_Helper u = SendReceive(13, m);
            return u.ReadInt32();
        }
        public int EfsUsePinForEncryptedFiles(Struct_4 p0, Struct_9 p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.Write_4(p0);
            m.Write_9(p1);
            _Unmarshal_Helper u = SendReceive(14, m);
            return u.ReadInt32();
        }
        public int EfsRpcAddUsersToFileEx(int p0, System.Nullable<Struct_8> p1, string p2, Struct_5 p3)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteInt32(p0);
            m.WriteReferent(p1, new System.Action<Struct_8>(m.Write_8));
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p2, "p2"));
            m.Write_5(p3);
            _Unmarshal_Helper u = SendReceive(15, m);
            return u.ReadInt32();
        }
        public int EfsRpcFileKeyInfoEx_16(int p0, System.Nullable<Struct_8> p1, string p2, int p3, out System.Nullable<Struct_8> p4)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteInt32(p0);
            m.WriteReferent(p1, new System.Action<Struct_8>(m.Write_8));
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p2, "p2"));
            m.WriteInt32(p3);
            _Unmarshal_Helper u = SendReceive(16, m);
            p4 = u.ReadReferentValue<Struct_8>(new System.Func<Struct_8>(u.Read_8), false);
            return u.ReadInt32();
        }
        public int EfsRpcFileKeyInfoEx_17(out System.Nullable<Struct_8> p0)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            _Unmarshal_Helper u = SendReceive(17, m);
            p0 = u.ReadReferentValue<Struct_8>(new System.Func<Struct_8>(u.Read_8), false);
            return u.ReadInt32();
        }
        public int EfsRpcFileKeyInfoEx_18(string p0, out System.Nullable<Struct_8> p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            _Unmarshal_Helper u = SendReceive(18, m);
            p1 = u.ReadReferentValue<Struct_8>(new System.Func<Struct_8>(u.Read_8), false);
            return u.ReadInt32();
        }
        public int EfsRpcFileKeyInfoEx_19(string p0, System.Nullable<Struct_8> p1, Struct_8 p2, System.Nullable<Struct_10> p3)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.WriteReferent(p1, new System.Action<Struct_8>(m.Write_8));
            m.Write_8(p2);
            m.WriteReferent(p3, new System.Action<Struct_10>(m.Write_10));
            _Unmarshal_Helper u = SendReceive(19, m);
            return u.ReadInt32();
        }
        public int EfsRpcFlushEfsCache()
        {
            _Marshal_Helper m = new _Marshal_Helper();
            _Unmarshal_Helper u = SendReceive(20, m);
            return u.ReadInt32();
        }
        public int EfsRpcEncryptFileExSrv(string p0, string p1, int p2)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.WriteReferent(p1, new System.Action<string>(m.WriteTerminatedString));
            m.WriteInt32(p2);
            _Unmarshal_Helper u = SendReceive(21, m);
            return u.ReadInt32();
        }
        public int EfsRpcQueryProtectors(string p0, out System.Nullable<Struct_11> p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            _Unmarshal_Helper u = SendReceive(22, m);
            p1 = u.ReadReferentValue<Struct_11>(new System.Func<Struct_11>(u.Read_11), false);
            return u.ReadInt32();
        }
        public int EfsRpcWriteFileWithHeaderRaw(NtApiDotNet.Ndr.Marshal.NdrContextHandle p0, NtApiDotNet.Ndr.Marshal.NdrPipe<sbyte> p1, Struct_8 p2, long p3, int p4)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteContextHandle(p0);
            m.Write_32(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p1, "p1"));
            m.Write_8(p2);
            m.WriteInt64(p3);
            m.WriteInt32(p4);
            _Unmarshal_Helper u = SendReceive(23, m);
            return u.ReadInt32();
        }
        public int EdpRpcCredentialCreate(string p0, string p1, string p2, out string p3)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p1, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p2, new System.Action<string>(m.WriteTerminatedString));
            _Unmarshal_Helper u = SendReceive(24, m);
            p3 = u.ReadReferent<string>(new System.Func<string>(u.ReadConformantVaryingString), false);
            return u.ReadInt32();
        }
        public int EdpRpcCredentialQuery(string p0, string p1, string p2, out string p3)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p1, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p2, new System.Action<string>(m.WriteTerminatedString));
            _Unmarshal_Helper u = SendReceive(25, m);
            p3 = u.ReadReferent<string>(new System.Func<string>(u.ReadConformantVaryingString), false);
            return u.ReadInt32();
        }
        public int EdpRpcCredentialExists(string p0, string p1, string p2, out int p3)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p1, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p2, new System.Action<string>(m.WriteTerminatedString));
            _Unmarshal_Helper u = SendReceive(26, m);
            p3 = u.ReadInt32();
            return u.ReadInt32();
        }
        public int EdpRpcCredentialDelete(int p0, string p1, string p2, string p3, string p4)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteInt32(p0);
            m.WriteReferent(p1, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p2, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p3, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p4, new System.Action<string>(m.WriteTerminatedString));
            _Unmarshal_Helper u = SendReceive(27, m);
            return u.ReadInt32();
        }
        public int EdpRpcQueryRevokedPolicyOwnerIds(string p0, int p1, out string p2)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            m.WriteInt32(p1);
            _Unmarshal_Helper u = SendReceive(28, m);
            p2 = u.ReadReferent<string>(new System.Func<string>(u.ReadConformantVaryingString), false);
            return u.ReadInt32();
        }
        public int EdpRpcQueryDplEnforcedPolicyOwnerIds(string p0, out string p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            _Unmarshal_Helper u = SendReceive(29, m);
            p1 = u.ReadReferent<string>(new System.Func<string>(u.ReadConformantVaryingString), false);
            return u.ReadInt32();
        }
        public int EdpRpcGetLockSessionWrappedKey(string p0, sbyte[] p1, int p2, out sbyte[] p3, out int p4, out sbyte[] p5, out int p6)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p1, new System.Action<sbyte[], long>(m.Write_33), p2);
            m.WriteInt32(p2);
            _Unmarshal_Helper u = SendReceive(30, m);
            p3 = u.ReadReferent<sbyte[]>(new System.Func<sbyte[]>(u.Read_34), false);
            p4 = u.ReadInt32();
            p5 = u.ReadReferent<sbyte[]>(new System.Func<sbyte[]>(u.Read_35), false);
            p6 = u.ReadInt32();
            return u.ReadInt32();
        }
        public int EdpRpcGetLockSessionUnwrappedKey(string p0, sbyte[] p1, int p2, sbyte[] p3, int p4, out sbyte[] p5, out int p6)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p1, new System.Action<sbyte[], long>(m.Write_33), p2);
            m.WriteInt32(p2);
            m.WriteReferent(p3, new System.Action<sbyte[], long>(m.Write_36), p4);
            m.WriteInt32(p4);
            _Unmarshal_Helper u = SendReceive(31, m);
            p5 = u.ReadReferent<sbyte[]>(new System.Func<sbyte[]>(u.Read_35), false);
            p6 = u.ReadInt32();
            return u.ReadInt32();
        }
        public int EdpRpcGetCredServiceState(out int p0, out int p1, out int p2, out int p3, out int p4, out int p5, out int p6, out int p7, out int p8)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            _Unmarshal_Helper u = SendReceive(32, m);
            p0 = u.ReadInt32();
            p1 = u.ReadInt32();
            p2 = u.ReadInt32();
            p3 = u.ReadInt32();
            p4 = u.ReadInt32();
            p5 = u.ReadInt32();
            p6 = u.ReadInt32();
            p7 = u.ReadInt32();
            p8 = u.ReadInt32();
            return u.ReadInt32();
        }
        public int EdpRpcDplUpgradePinInfo(string p0, out int p1, out int p2, out int p3)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            _Unmarshal_Helper u = SendReceive(33, m);
            p1 = u.ReadInt32();
            p2 = u.ReadInt32();
            p3 = u.ReadInt32();
            return u.ReadInt32();
        }
        public int EdpRpcDplUpgradeVerifyUser(string p0, string p1, out int p2, out NtApiDotNet.Ndr.Marshal.NdrUInt3264 p3)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p1, new System.Action<string>(m.WriteTerminatedString));
            _Unmarshal_Helper u = SendReceive(34, m);
            p2 = u.ReadInt32();
            p3 = u.ReadUInt3264();
            return u.ReadInt32();
        }
        public int EdpRpcDplUserCredentialsSet(string p0, string p1, NtApiDotNet.Ndr.Marshal.NdrEnum16 p2, NtApiDotNet.Ndr.Marshal.NdrUInt3264 p3)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p1, new System.Action<string>(m.WriteTerminatedString));
            m.WriteEnum16(p2);
            m.WriteUInt3264(p3);
            _Unmarshal_Helper u = SendReceive(35, m);
            return u.ReadInt32();
        }
        public int EdpRpcDplUserUnlockStart(string p0, string p1, long p2, out NtApiDotNet.Ndr.Marshal.NdrUInt3264 p3)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p1, new System.Action<string>(m.WriteTerminatedString));
            m.WriteInt64(p2);
            _Unmarshal_Helper u = SendReceive(36, m);
            p3 = u.ReadUInt3264();
            return u.ReadInt32();
        }
        public int EdpRpcDplUserUnlockComplete(string p0, int p1, NtApiDotNet.Ndr.Marshal.NdrUInt3264 p2)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            m.WriteInt32(p1);
            m.WriteUInt3264(p2);
            _Unmarshal_Helper u = SendReceive(37, m);
            return u.ReadInt32();
        }
        public int EdpRpcQueueFileForEncryption(System.Nullable<Struct_13> p0, string p1, string p2, string p3)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<Struct_13>(m.Write_13));
            m.WriteReferent(p1, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p2, new System.Action<string>(m.WriteTerminatedString));
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p3, "p3"));
            _Unmarshal_Helper u = SendReceive(38, m);
            return u.ReadInt32();
        }
        public int EdpRpcServiceFileEncryptionQueue(sbyte p0)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteSByte(p0);
            _Unmarshal_Helper u = SendReceive(39, m);
            return u.ReadInt32();
        }
        public int EdpRpcCredSvcControl(int p0, string p1, string p2, sbyte[] p3, int p4, sbyte[] p5, int p6, out sbyte[] p7, out int p8)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteInt32(p0);
            m.WriteReferent(p1, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p2, new System.Action<string>(m.WriteTerminatedString));
            m.WriteReferent(p3, new System.Action<sbyte[], long>(m.Write_36), p4);
            m.WriteInt32(p4);
            m.WriteReferent(p5, new System.Action<sbyte[], long>(m.Write_37), p6);
            m.WriteInt32(p6);
            _Unmarshal_Helper u = SendReceive(40, m);
            p7 = u.ReadReferent<sbyte[]>(new System.Func<sbyte[]>(u.Read_38), false);
            p8 = u.ReadInt32();
            return u.ReadInt32();
        }
        public int EdpRpcRmsClearKeys()
        {
            _Marshal_Helper m = new _Marshal_Helper();
            _Unmarshal_Helper u = SendReceive(41, m);
            return u.ReadInt32();
        }
        public int EdpRpcRmsContainerizeFile(string p0, string p1, string p2, string p3, out string p4)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p1, "p1"));
            m.WriteReferent(p2, new System.Action<string>(m.WriteTerminatedString));
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p3, "p3"));
            _Unmarshal_Helper u = SendReceive(42, m);
            p4 = u.ReadReferent<string>(new System.Func<string>(u.ReadConformantVaryingString), false);
            return u.ReadInt32();
        }
        public int EdpRpcRmsGetContainerIdentity(string p0, out string p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            _Unmarshal_Helper u = SendReceive(43, m);
            p1 = u.ReadReferent<string>(new System.Func<string>(u.ReadConformantVaryingString), false);
            return u.ReadInt32();
        }
        public int EdpRpcRmsDecontainerizeFile(string p0, string p1, out string p2)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p1, "p1"));
            _Unmarshal_Helper u = SendReceive(44, m);
            p2 = u.ReadReferent<string>(new System.Func<string>(u.ReadConformantVaryingString), false);
            return u.ReadInt32();
        }
        public int EdpRpcAllowFileAccessForProcess(string p0, int p1, string p2)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.WriteInt32(p1);
            m.WriteReferent(p2, new System.Action<string>(m.WriteTerminatedString));
            _Unmarshal_Helper u = SendReceive(45, m);
            return u.ReadInt32();
        }
        public int EdpRpcGetTfaCache(out System.Nullable<Struct_14> p0)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            _Unmarshal_Helper u = SendReceive(46, m);
            p0 = u.ReadReferentValue<Struct_14>(new System.Func<Struct_14>(u.Read_14), false);
            return u.ReadInt32();
        }
        public int EdpRpcUnprotectFile(string p0, int p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.WriteInt32(p1);
            _Unmarshal_Helper u = SendReceive(47, m);
            return u.ReadInt32();
        }
        public int EdpRpcPurgeAppLearningEvents()
        {
            _Marshal_Helper m = new _Marshal_Helper();
            _Unmarshal_Helper u = SendReceive(48, m);
            return u.ReadInt32();
        }
        public int OefsRpcCheckSupport(string p0, out int p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            _Unmarshal_Helper u = SendReceive(49, m);
            p1 = u.ReadInt32();
            return u.ReadInt32();
        }
        public int EdpRpcWriteLogSiteLearningEvents(string p0)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            _Unmarshal_Helper u = SendReceive(50, m);
            return u.ReadInt32();
        }
        public int EfsRpcReprotectFile(string p0, string p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p0, "p0"));
            m.WriteTerminatedString(NtApiDotNet.Win32.Rpc.RpcUtils.CheckNull(p1, "p1"));
            _Unmarshal_Helper u = SendReceive(51, m);
            return u.ReadInt32();
        }
        public int EdpRpcIsConsumerProtectionEnforced(string p0, out int p1)
        {
            _Marshal_Helper m = new _Marshal_Helper();
            m.WriteReferent(p0, new System.Action<string>(m.WriteTerminatedString));
            _Unmarshal_Helper u = SendReceive(52, m);
            p1 = u.ReadInt32();
            return u.ReadInt32();
        }
    }
    #endregion
}

