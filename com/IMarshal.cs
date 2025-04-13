using System.Runtime.InteropServices;

namespace TotalPotato
{

    [Guid("00000003-0000-0000-C000-000000000046")]
    [InterfaceType(1)]
    [ComConversionLoss]
    [ComImport]
    public interface IMarshal
    {

        void GetUnmarshalClass([In] ref Guid riid, [In] nint pv, [In] uint dwDestContext, [In] nint pvDestContext, [In] uint MSHLFLAGS, out Guid pCid);
        void GetMarshalSizeMax([In] ref Guid riid, [In] nint pv, [In] uint dwDestContext, [In] nint pvDestContext, [In] uint MSHLFLAGS, out uint pSize);
        void MarshalInterface([MarshalAs(28)][In] IStreamCom pstm, [In] ref Guid riid, [In] nint pv, [In] uint dwDestContext, [In] nint pvDestContext, [In] uint MSHLFLAGS);
        void UnmarshalInterface([MarshalAs(28)][In] IStreamCom pstm, [In] ref Guid riid, out nint ppv);
        void ReleaseMarshalData([MarshalAs(28)][In] IStreamCom pstm);
        void DisconnectObject([In] uint dwReserved);
    }
}
