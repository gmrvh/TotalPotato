# TotalPotato

**TotalPotato** is a minimal Windows privilege escalation tool that combines techniques from **SweetPotato** and **GodPotato** to trigger NT AUTHORITY\SYSTEM execution via EfsRpc abuse.
This was built to assist in CTF challanges and OSCP-like machines, not battle-tested.

## Features

- Combines SweetPotato and GodPotato methods
- Uses EfsRpc (EncryptFileSrv) impersonation
- No external dependencies

Original exploit code is sourced from the GodPotato and SweetPotato repos.

## Credits

- [**GodPotato**](https://github.com/BeichenDream/GodPotato) — discovered and implemented by **BeichenDream**  
  Exploits the **DCOM/NTLM relay** behavior to achieve privilege escalation on Windows.

- [**SweetPotato**](https://github.com/CCob/SweetPotato) — developed by **@CCob** (James Forshaw also contributed research around the EfsRpc abuse)  
  Implements **EfsRpc abuse** (e.g., `EfsRpcOpenFileRaw`, `EfsRpcEncryptFileSrv`) for SYSTEM-level privilege escalation using named pipe impersonation.
