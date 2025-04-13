﻿using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace TotalPotato
{
    [ComImport, Guid("0000000c-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IStreamCom
    {
        void Read([Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pv, uint cb, out uint pcbRead);
        void Write([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pv, uint cb, out uint pcbWritten);
        void Seek(long dlibMove, uint dwOrigin, out long plibNewPosition);
        void SetSize(long libNewSize);
        void CopyTo(IStreamCom pstm, long cb, out long pcbRead, out long pcbWritten);
        void Commit(uint grfCommitFlags);
        void Revert();
        void LockRegion(long libOffset, long cb, uint dwLockType);
        void UnlockRegion(long libOffset, long cb, uint dwLockType);
        void Stat(out STATSTG pstatstg, uint grfStatFlag);
        void Clone(out IStreamCom ppstm);
    }
}
