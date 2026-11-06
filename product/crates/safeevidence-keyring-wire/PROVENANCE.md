# Provenance: safeevidence-keyring-wire

SafeEvidence-written (GREENFIELD_JUSTIFIED). No donor code. Sources inspected: T03's Linux adapter, which calls Secret Service in-process and has no IPC, and T10's row, whose sandbox plans and worker policy define no such channel. No
other row in `docs/plan/SOURCE_TRANSPLANT_MATRIX_V1.md` names a keyring helper or stdio protocol, and this was a search of that matrix, not of every donor. This boundary exists only because the core must open no sockets, and it is a fixed frame
format of about 270 lines plus tests.

The framed protocol between the vault and the Linux keyring helper, over the helper's stdin and stdout. It carries protected records, which hold key
material. Its frames are zeroized when dropped, and `Debug` redacts records. Callers must not pass it a buffered reader or writer, and the OS pipe buffer is outside this.
