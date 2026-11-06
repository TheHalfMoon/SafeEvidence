# Provenance: safeevidence-keyring-wire

SafeEvidence-written (GREENFIELD_JUSTIFIED: this boundary exists only because the core must open no sockets). No donor code.

The framed protocol between the vault and the Linux keyring helper, over the helper's stdin and stdout. It carries protected records, which hold key
material, so frames are zeroized in process. The OS pipe buffer is outside that.
