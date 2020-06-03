# Windows-API-Programming

Some Questions Related to Windows API Programming(For reference):

What is Luid??

A logon session is created when a user account or service account is authenticated to Windows.

An access token is created along with the logon session to represent the account’s security context. The access token is duplicated for use by processes and threads that run under that security context, and it includes a reference back to its logon session. A logon session remains active as long as there is a duplicated token that references it.

Each logon session has a locally-unique identifier (LUID). A LUID is a system-generated 64-bit value guaranteed to be unique during a single boot session on the system on which it was generated. Some LUIDs are predefined. For example, the LUID for the System account’s logon session is always 0x3e7 (999 decimal), the LUID for Network Service’s session is 0x3e4 (996), and Local Service’s is 0x3e5 (997). Most other LUIDs are randomly generated.
