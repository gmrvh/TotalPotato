using System.Runtime.InteropServices;

namespace TotalPotato
{
    [ComVisible(false)]
    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("0000000A-0000-0000-C000-000000000046")]
    public interface ILockBytes
    {
        //Note: These two by(reference 32-bit integers (ULONG) could be used as return values instead,
        //      but they are not tagged [retval] in the IDL, so for consitency's sake...
        void ReadAt(long ulOffset, nint pv, int cb, out uint pcbRead);
        void WriteAt(long ulOffset, nint pv, int cb, out uint pcbWritten);
        void Flush();
        void SetSize(long cb);
        void LockRegion(long libOffset, long cb, int dwLockType);
        void UnlockRegion(long libOffset, long cb, int dwLockType);
        void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG pstatstg, int grfStatFlag);

    }


}
