# PointyTokenz

## Description

- This is a small spaghetti-coded tool to manipulate Windows Access Tokens that I have made while completing the "Windows Access Tokens" course from ZeroPoint Security by @rasta-mouse.
- This tool does not introduce any new or groundbreaking techniques; it was created purely for practice and learning.
- It is made in C# targeting .NET Framework 4.7.2 and initially relied only on [csWin32](https://microsoft.github.io/CsWin32/docs/getting-started.html) to generate P/Invoke calls, as Rasta piqued my interest in it. However, some parts were implemented manually where csWin32 was impractical (e.g., WindowStation DACL logic from RunAsCs).

## Purpose

- Q: Every decent C2 implant has built-in token manipulation capabilities, and with so many good tools out there like RunAsCs, why even bother?
- A: It felt like a great way to apply the knowledge of the course and it was FUN. Also, I don't have a programming background, so this was a great opportunity to become more familiar with C#/.NET, the Windows API, GitHub, and related tools.

## Credits

- @rasta-mouse/ZPS for the great course, I learned a lot from it and quite enjoyed applying the knowledge to this tool as I went along.
- The [Rubeus](https://github.com/GhostPack/Rubeus) project for the command structure and commandline parsing logic, I was not interested in figuring this out for now.
- @antonioCoco and his [RunAsCs](https://github.com/antonioCoco/RunasCs) project, which I used as a reference for the ``runasadmin`` command. I have also completely ripped off the WindowStation DACL logic from RunAsCs to fix some issues I was having with spawning processes with `make` and `steal`, and there was no way I would have come out with this magic myself.

## Usage

- I have tested this inside a Sliver implant with `execute-assembly` and `inline-execute-assembly` and it seemed to generally work fine, but impersonating the token in the current thread may cause some issues. It is better used to spawn processes in that scenario. 
- Obviously, it is probably better to use the implant's built-in token manipulation capabilities instead of this tool, but I wanted to test it out.

- The table below summarizes the different impersonation methods implemented and their behavior:

| Command    | Execution | API                                              | Impersonation          | UAC applied                                 |
| ---------- | --------- | ------------------------------------------------ | ---------------------- | ------------------------------------------- |
| runas      | Yes       | CreateProcessWithLogon                           | No                     | Yes, except for RID500                      |
| runasadmin | Yes       | LogonUser + shenanigans + CreateProcessWithLogon | No                     | No                                          |
| steal      | Yes       | CreateProcessWithToken or CreateProcessAsUser    | Yes, but kinda useless | Yes, except for RID500                      |
| make       | Yes       | CreateProcessWithToken or CreateProcessAsUser    | Yes, but kinda useless | Yes, except for RID500 OR when using Cached |

```
  _____      _       _      _______    _
 |  __ \    (_)     | |    |__   __|  | |
 | |__) |__  _ _ __ | |_ _   _| | ___ | | _____ _ __  ____
 |  ___/ _ \| | '_ \| __| | | | |/ _ \| |/ / _ \ '_ \|_  /
 | |  | (_) | | | | | |_| |_| | | (_) |   <  __/ | | |/ /
 |_|   \___/|_|_| |_|\__|\__, |_|\___/|_|\_\___|_| |_/___|
                          __/ |
                         |___/

                    Version 0.0.1


[*] Action: help


PointyTokenz.exe - Manage and manipulate process tokens.

Available Commands:
  help       - Show this help message.
  make       - Create a primary access token and duplicate it to an impersonation token, then impersonate it or spawn a process with it.
  enum       - Enumerate the privileges of a target process token.
  adjust     - Adjust the privileges of a process token.
  steal      - Steal and duplicate the primary token of a target process, then impersonate it or spawn a process with it.
  runas      - Run a command as another user using plaintext credentials.
  runasadmin - Run a command as an administrator with elevated privileges using plaintext credentials (UAC Bypass).
  revert     - Revert to the process token. Used to drop impersonation from "steal" or "make".

Usage:
  PointyTokenz.exe <command> [options]
  PointyTokenz.exe <command> /help (for detailed command usage)

Examples:
  PointyTokenz.exe help
  PointyTokenz.exe adjust /help
  PointyTokenz.exe adjust /privilege:SeDebugPrivilege /action:enable /pid:1234
```

### Make

```
[*] Command: make

Action:
 Create a primary access token from plaintext credentials, duplicate it to a primary token, and impersonate it.
 If the /spawn argument is present, then attempt to spawn a process with the created token instead.

 IMPORTANT NOTE: Without /spawn, it will impersonate the token in the current thread, which may do wonky things, especially inside an implant.
     You probably want /spawn in most cases, but I left a placeholder to insert some logic in the case of impersonation.

Requirements:
 Spawning a process using CreateProcessWithToken (default) requires the SeImpersonatePrivilege privilege.
 If that call fails, CreateProcessAsUser will be used as a fallback, which requires SeIncreaseQuotaPrivilege and SeAssignPrimaryTokenPrivilege. (not much testing of this was done)

Purpose:
 To run a command as another user from plaintext credentials, you are probably better off with "runas" or "runasadmin".
 This was mostly added for experimenting with another way to spawn a process using a token.
 Interestingly though, using this with the "Cached" logon type to spawn a process as another admin user will result in a high integrity process (even if not RID-500).

Options:
 /username:<username>  - The username to use for the new token (required)
 /password:<password>  - The password to use for the new token (optional in the API but needed for interactive sessions)
 /domain:<domain>      - The domain to use for the new token (optional, defaults to machine name)
 /logontype:<type>     - The logon type to use for the new token (optional - defaults to LOGON32_LOGON_INTERACTIVE)
 /tokentype:<type>     - The type of token to duplicate into. (optional, defaults to Primary)
 /spawn:<command>      - The command to spawn as the impersonated user (optional - defaults to cmd.exe)
 /netonly              - Use LOGON_NETCREDENTIALS_ONLY for the spawned process (optional)
 /help                 - Show this help message.

Supported logon types:
 Interactive     - LOGON32_LOGON_INTERACTIVE (needed for local impersonation)
 NewCredentials  - LOGON32_LOGON_NEW_CREDENTIALS (network impersonation only)
 Network         - LOGON32_LOGON_NETWORK (untested)
 Cached          - LOGON32_LOGON_NETWORK_CLEARTEXT (can be used for UAC bypass)
 ```
	
### Enum

```
[*] Command: enum

Action:
 Enumerate the primary access token of a target process PID.

Requirements:
 High Integrity will be required to query processes other than your own.

Options:
 /pid:<pid>  - The process ID of the target process (required)
 ```

 ### Adjust

 ```
 [*] Command: adjust

Action:
 Adjust the privileges of the primary token of a target process.

Requirements:
 The privilege must already be assigned to the target process.

Options:
 /privilege:<privilege> - The name of the privilege to adjust. (required)
 /action:<action>       - The action to perform on the privilege. (required)
 /pid:<pid>             - The process ID to adjust the token of. (required)
 /help                  - Show this help message.

Supported actions:
 enable  - Enable the privilege
 disable - Disable the privilege
 remove  - Remove the privilege
 ```

 ### Steal

 ```
 [*] Command: steal

Action:
 Steal the primary access token of a target process, duplicate it, and impersonate it.
 If the /spawn argument is present, then attempt to spawn a process with the stolen token instead.

 IMPORTANT NOTE: Without /spawn, it will impersonate the token in the current thread, which may do wonky things, especially inside an implant.
     You probably want /spawn in most cases, but I left a placeholder to insert some logic in the case of impersonation.

Requirements:
 The calling process must be running in High Integrity and have SeDebugPrivilege. Some processes still won't be "stealable" due to permissions and ownership.
 Spawning a process using CreateProcessWithToken (default) requires the SeImpersonatePrivilege privilege.
 If that call fails, CreateProcessAsUser will be used as a fallback, which requires SeIncreaseQuotaPrivilege and SeAssignPrimaryTokenPrivilege. (not much testing of this was done)

Purpose:
 Useful for running a command/implant as a logged-on user without knowing their credentials.
 It can also be used to get SYSTEM access by stealing the token of a SYSTEM process.

Options:
 /pid:<pid>        - The process ID to steal the access token from. (required)
 /spawn:<program>  - The command to spawn as the impersonated user (optional - defaults to cmd.exe)
 /tokentype:<type> - The type of token to steal. (optional, defaults to Primary)
 /netonly          - Use LOGON_NETCREDENTIALS_ONLY for the spawned process. (optional)
 /help             - Show this help message.

Supported token types:
 Primary        - TokenPrimary (default)
 Impersonation  - TokenImpersonation
 ```

 ### RunAs
 
 ```
  [*] Command: runas

Action:
 Run a command as another user with plaintext credentials using CreateProcessWithLogon.

Requirements:
 The supplied user must have the Log On Locally permission.

Purpose:
 This is useful for running a command as another user without having to interactively log in.
 This can also be used to spawn a process using LOGON_NETCREDENTIALS_ONLY to impersonate the user only for network access. (with /netonly)

Options:
 /username:<username>  - The username to run the command as. (required)
 /password:<password>  - The password of the user. (required)
 /domain:<domain>      - The domain of the user. (optional, defaults to machine name)
 /command:<command>    - The command to run as the user. (required)
 /netonly              - Run the command with network credentials only. (optional - defaults to LOGON_WITH_PROFILE)
 /help                 - Show this help message.
 ```

 ### RunAsAdmin

 ```
 [*] Command: runasadmin

Action:
 Run a command as an administrator with elevated privileges using plaintext credentials.
 Credits to @antonioCoco for the technique (https://github.com/antonioCoco/RunasCs/)

Requirements:
 Requires plaintext credentials of a local administrator user, not necessarily RID-500.

Purpose:
 This is useful for running a command as an administrator without having to interactively log in.
 This command also bypasses UAC and results in an elevated process, and is usable even from a non admin user in medium integrity.

Options:
 /username:<username>  - The username to run the command as (local admin required). (required)
 /password:<password>  - The password of the user. (required)
 /domain:<domain>      - The domain of the user. (optional, defaults to machine name)
 /command:<command>    - The command to run as the user. (optional, defaults to cmd.exe)
 /help                 - Show this help message.
 ```

 ### Revert

 ```
 [*] Command: revert

Action:
 Revert to the process token. Used to drop impersonation from "steal" or "make".
 ```

 ## TODO

 - I would like to learn some more about the WindowStation DACL shenanigans.
 - In the future, I might implement some of these techniques in the form of BOFs to learn the basics of BOF development.