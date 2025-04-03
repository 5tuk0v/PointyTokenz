using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.System.Threading;
using System.Security.Principal;
using Windows.Win32.System.Memory;
using System.Runtime.InteropServices;
using PointyTokenz.Domain;
using Microsoft.Win32.SafeHandles;

using static Windows.Win32.PInvoke;

namespace PointyTokenz.Commands
{
    public class Enumerate : ICommand
    {
        public static string CommandName => "enum";
        public unsafe void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Command: enum\r\n");
            string pidStr = "";

            // Parse the command line arguments
            if (arguments.ContainsKey("/pid"))
            {
                pidStr = arguments["/pid"];
            }

            // If the help flag is set, or PID is empty, print the help message
            if (arguments.ContainsKey("/help") || string.IsNullOrEmpty(pidStr))
            {
                Console.WriteLine("Action:");
                Console.WriteLine(" Enumerate the primary access token of a target process PID.\r\n");

                Console.WriteLine("Requirements:");
                Console.WriteLine(" High Integrity will be required to query processes other than your own.\r\n");

                Console.WriteLine("Options:");
                Console.WriteLine(" /pid:<pid>  - The process ID of the target process (required)");

                return;
            }

            // Convert the PID to an integer
            if (!int.TryParse(pidStr, out int pid))
            {
                // Print an error if the PID is invalid
                Console.WriteLine("[x] Failed to parse the PID");
                return;
            }

            // Open the process and get the token handle
            var procHandle = OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_INFORMATION, false, (uint)pid);
            if (procHandle.IsNull)
            {
                Console.WriteLine($"[x] Failed to open process {pid} : {Marshal.GetLastWin32Error()}");
                return;
            }

            // Using Safe Handles because... csWin32???
            SafeFileHandle safeProcessHandle = new SafeFileHandle(procHandle, true);
            SafeFileHandle tokenHandle;

            // Open the process token
            if (!OpenProcessToken(safeProcessHandle, TOKEN_ACCESS_MASK.TOKEN_QUERY, out tokenHandle))
            {
                Console.WriteLine($"[x] Failed to open process token : {Marshal.GetLastWin32Error()}");
                CloseHandle(procHandle);
                return;
            }

            // Debug statement
            Console.WriteLine("[*] Successfully opened process token.");

            // Get the user information from the token
            // Call the Helper function to get the token information for the TokerUser class
            SecurityIdentifier? sid = null;
            NTAccount? user = null;

            // Get the TOKEN_USER structure using the helper function
            if (Helpers.TokenInfo(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser, out TOKEN_USER tokenUser))
            {
                // Getting the user's SID and translating it to an NTAccount
                sid = new SecurityIdentifier(tokenUser.User.Sid);
                user = (NTAccount)sid.Translate(typeof(NTAccount));
            }
            else
            {
                Console.WriteLine("[x] Failed to retrieve token user information.");
            }

            // Get the token statistics 
            if (!Helpers.TokenInfo(tokenHandle, TOKEN_INFORMATION_CLASS.TokenStatistics, out TOKEN_STATISTICS tokenStats))
            {
                Console.WriteLine("[x] Failed to retrieve token statistics.");
            }

            // Get the token origin
            if (!Helpers.TokenInfo(tokenHandle, TOKEN_INFORMATION_CLASS.TokenOrigin, out TOKEN_ORIGIN tokenOrigin))
            {
                Console.WriteLine("[x] Failed to retrieve token origin.");
            }

            // Get the token integrity level
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

            // Printing the process information
            Console.WriteLine("Process ID          : {0}", pid);

            // Printing the token information
            Console.WriteLine("User                : {0}", user.Value);
            Console.WriteLine("User SID            : {0}", sid.Value);
            Console.WriteLine("Token Type          : {0}", tokenStats.TokenType);
            Console.WriteLine("Impersonation Level : {0}", tokenStats.TokenType is TOKEN_TYPE.TokenImpersonation ? tokenStats.ImpersonationLevel : "N/A");
            Console.WriteLine("Token Id            : {0:X8}-{1:X8}", tokenStats.TokenId.HighPart, tokenStats.TokenId.LowPart);
            Console.WriteLine("Authentication Id   : {0:X8}-{1:X8}", tokenStats.AuthenticationId.HighPart, tokenStats.AuthenticationId.LowPart);
            Console.WriteLine("Origin Logon Id     : {0:X8}-{1:X8}", tokenOrigin.OriginatingLogonSession.HighPart, tokenOrigin.OriginatingLogonSession.LowPart);
            Console.Write("Integrity Level     : ");

            switch (*subAuth)
            {
                case >= SECURITY_MANDATORY_SYSTEM_RID:
                    Console.WriteLine("SYSTEM");
                    break;

                case >= SECURITY_MANDATORY_HIGH_RID:
                    Console.WriteLine("High");
                    break;

                case >= SECURITY_MANDATORY_MEDIUM_RID:
                    Console.WriteLine("Medium");
                    break;

                case >= SECURITY_MANDATORY_LOW_RID:
                    Console.WriteLine("Low");
                    break;

                default:
                    Console.WriteLine("Untrusted");
                    break;
            }

            Console.WriteLine("Is Elevated         : {0}", tokenElevation.TokenIsElevated != 0 ? "True" : "False");
            Console.WriteLine("Elevation Type      : {0}", tokenElevationType);

            // If the token elevation type is not Default, we need to get the linked token
            if (tokenElevationType is not TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault)
            {
                // Get the linked token information with the helper function
                if (!Helpers.TokenInfo(tokenHandle, TOKEN_INFORMATION_CLASS.TokenLinkedToken, out TOKEN_LINKED_TOKEN tokenLinked))
                {
                    Console.WriteLine("[x] Failed to retrieve linked token information.");
                }
                else
                {
                    // Print the linked token handle
                    Console.WriteLine("Linked Token Handle : 0x{0:X8}", (IntPtr)tokenLinked.LinkedToken.Value);
                    // Close the linked token handle
                    CloseHandle(tokenLinked.LinkedToken);
                }
            }

            // Get the token privileges using the helper function
            // I seem to have issues with the structure returned by TokenInfo for this one, keeping csWin32 calls for now because too noob to fix
            /*if (!Helpers.TokenInfo(tokenHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, out TOKEN_PRIVILEGES tokenPrivileges))
            {
                Console.WriteLine("[x] Failed to retrieve token privileges.");
            }
            else
            {
                // Print the token privileges count
                Console.WriteLine("Privilege Count     : {0}\n", tokenPrivileges.PrivilegeCount);

                // Print the content of the tokenPrivileges structure
                // Print the structure coming from TokenInfo
                Console.WriteLine("[*] TokenInfo Structure:");
                for (var i = 0; i < tokenPrivileges.PrivilegeCount; i++)
                {
                    var lpPrivilege = tokenPrivileges.Privileges[i];
                    Console.WriteLine($"    LUID: {lpPrivilege.Luid.LowPart}-{lpPrivilege.Luid.HighPart}, Attributes: {lpPrivilege.Attributes}");
                }
            }*/


            // Get the required buffer size for the token privileges
            var returnLengthPrivileges = 0U;

            if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, null, 0U, out returnLengthPrivileges) 
                && (WIN32_ERROR)Marshal.GetLastWin32Error() != WIN32_ERROR.ERROR_INSUFFICIENT_BUFFER)
            {
                Console.WriteLine("[x] Failed to retrieve buffer size.");
            }

            // Allocate the buffer for the token privileges
            var tokenPrivileges = (TOKEN_PRIVILEGES*)LocalAlloc(LOCAL_ALLOC_FLAGS.LMEM_FIXED, returnLengthPrivileges);

            // Get the token privileges
            if (!GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, tokenPrivileges, returnLengthPrivileges, out returnLengthPrivileges))
            {
                Console.WriteLine("[x] Failed to retrieve token privileges.");
                tokenHandle.Dispose();
                safeProcessHandle.Dispose();
                CloseHandle(procHandle);
                return;
            }

            Console.WriteLine("Privilege Count     : {0}\n", tokenPrivileges->PrivilegeCount);

            // Debugging stuff
            /*Console.WriteLine("[*] GetTokenInformation Structure:");
            for (var i = 0; i < tokenPrivileges->PrivilegeCount; i++)
            {
                var lpPrivilege = tokenPrivileges->Privileges[i];
                Console.WriteLine($"    LUID: {lpPrivilege.Luid.LowPart}-{lpPrivilege.Luid.HighPart}, Attributes: {lpPrivilege.Attributes}");
            }*/

            // Go through the privileges, resolve the names and print them
            for (var i = 0; i < tokenPrivileges->PrivilegeCount; i++)
            {
                var privilegeEntry = tokenPrivileges->Privileges[i];
                var nameSize = 256U;
                var nameBuffer = new char[nameSize];

                fixed (char* nameBufferPointer = nameBuffer)
                {
                    // resolve the privilege name from the LUID
                    LookupPrivilegeName(null, &privilegeEntry.Luid, nameBufferPointer, &nameSize);
                }

                var name = new string(nameBuffer, 0, (int)nameSize);

                // Print the name and attributes
                Console.WriteLine("    {0} [ {1} ]", name, privilegeEntry.Attributes);
            }

            // Cleanup
            tokenHandle.Dispose();
            safeProcessHandle.Dispose();
            CloseHandle(procHandle);
        }
    }
}
