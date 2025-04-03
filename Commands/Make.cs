using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Windows.Win32.Security;
using Windows.Win32.System.Threading;
using PointyTokenz.Domain;
using Windows.Win32.Foundation;

using static Windows.Win32.PInvoke;
using static PointyTokenz.Domain.Helpers;

namespace PointyTokenz.Commands
{
    public class Make : ICommand
    {
        public static string CommandName => "make";
        private WindowStationDACL? stationDaclObj;
        public unsafe void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Command: make\r\n");

            string username = "";
            string domain = Environment.MachineName; // Default to machine name
            string password = "";
            LOGON32_LOGON logonType = LOGON32_LOGON.LOGON32_LOGON_INTERACTIVE; // Default logon type

            // Parse the command line arguments
            if (arguments.ContainsKey("/help"))
            {
                Console.WriteLine("Action:");
                Console.WriteLine(" Create a primary access token from plaintext credentials, duplicate it to a primary token, and impersonate it.\r");
                Console.WriteLine(" If the /spawn argument is present, then attempt to spawn a process with the created token instead.\r\n");
                Console.WriteLine(" IMPORTANT NOTE: Without /spawn, it will impersonate the token in the current thread, which may do wonky things, especially inside an implant.\r");
                Console.WriteLine("     You probably want /spawn in most cases, but I left a placeholder to insert some logic in the case of impersonation.\r\n");

                Console.WriteLine("Requirements:");
                Console.WriteLine(" Spawning a process using CreateProcessWithToken (default) requires the SeImpersonatePrivilege privilege.");
                Console.WriteLine(" If that call fails, CreateProcessAsUser will be used as a fallback, which requires SeIncreaseQuotaPrivilege and SeAssignPrimaryTokenPrivilege. (not much testing of this was done)\r\n");

                Console.WriteLine("Purpose:");
                Console.WriteLine(" To run a command as another user from plaintext credentials, you are probably better off with \"runas\" or \"runasadmin\".");
                Console.WriteLine(" This was mostly added for experimenting with another way to spawn a process using a token.");
                Console.WriteLine(" Interestingly though, using this with the \"Cached\" logon type to spawn a process as another admin user will result in a high integrity process (even if not RID-500).\r\n");

                Console.WriteLine("Options:");
                Console.WriteLine(" /username:<username>  - The username to use for the new token (required)");
                Console.WriteLine(" /password:<password>  - The password to use for the new token (optional in the API but needed for interactive sessions)");
                Console.WriteLine(" /domain:<domain>      - The domain to use for the new token (optional, defaults to machine name)");
                Console.WriteLine(" /logontype:<type>     - The logon type to use for the new token (optional - defaults to LOGON32_LOGON_INTERACTIVE)");
                Console.WriteLine(" /tokentype:<type>     - The type of token to duplicate into. (optional, defaults to Primary)");
                Console.WriteLine(" /spawn:<command>      - The command to spawn as the impersonated user (optional - defaults to cmd.exe)");
                Console.WriteLine(" /netonly              - Use LOGON_NETCREDENTIALS_ONLY for the spawned process (optional)");
                Console.WriteLine(" /help                 - Show this help message.\r\n");

                Console.WriteLine("Supported logon types:");
                Console.WriteLine(" Interactive     - LOGON32_LOGON_INTERACTIVE (needed for local impersonation)");
                Console.WriteLine(" NewCredentials  - LOGON32_LOGON_NEW_CREDENTIALS (network impersonation only)");
                Console.WriteLine(" Network         - LOGON32_LOGON_NETWORK (untested)");
                Console.WriteLine(" Cached          - LOGON32_LOGON_NETWORK_CLEARTEXT (can be used for UAC bypass)\r\n");

                return;
            }

            if (arguments.ContainsKey("/username"))
            {
                username = arguments["/username"];

                if (arguments.ContainsKey("/password"))
                {
                    password = arguments["/password"];
                }
                if (arguments.ContainsKey("/domain"))
                {
                    domain = arguments["/domain"];
                }
                if (arguments.ContainsKey("/logontype"))
                {
                    // Parse the logon type from the arguments
                    string logonTypeString = arguments["/logontype"].ToLower();

                    // Use a switch statement to set the logon type based on the argument
                    switch (logonTypeString)
                    {
                        case "interactive":
                            logonType = LOGON32_LOGON.LOGON32_LOGON_INTERACTIVE;
                            break;

                        case "newcredentials":
                            logonType = LOGON32_LOGON.LOGON32_LOGON_NEW_CREDENTIALS;
                            break;

                        case "network":
                            logonType = LOGON32_LOGON.LOGON32_LOGON_NETWORK;
                            break;

                        case "cached":
                            logonType = LOGON32_LOGON.LOGON32_LOGON_NETWORK_CLEARTEXT;
                            break;

                        default:
                            Console.WriteLine("Invalid logon type specified. Supported values are 'Interactive', 'NewCredentials', 'Network', and 'Cached'.");
                            return;
                    }
                }
            }
            else
            {
                Console.WriteLine("[x] /username is required for this action.");
                return;
            }

            // Override the logon type to LOGON32_LOGON_NEW_CREDENTIALS if /netonly is specified
            if (arguments.ContainsKey("/netonly"))
            {
                logonType = LOGON32_LOGON.LOGON32_LOGON_NEW_CREDENTIALS;
            }

            // Getting the /tokentype argument from the input
            string tokenType = arguments.ContainsKey("/tokentype") ? arguments["/tokentype"] : "Primary";  // Default to "Primary" if not present

            // Validate the tokenType
            if (tokenType.Equals("Primary", StringComparison.OrdinalIgnoreCase))
            {
                tokenType = "Primary";  // This will be true if the argument is "Primary"
            }
            else if (tokenType.Equals("Impersonation", StringComparison.OrdinalIgnoreCase))
            {
                tokenType = "Impersonation";  // This will be true if the argument is "Impersonation"
            }
            else
            {
                Console.WriteLine("[x] Invalid /tokentype value. Supported values are 'Primary' and 'Impersonation'.");
                return;
            }

            // Create a token for the user specified 
            // Should return a primary token except when using LOGON32_LOGON_NETWORK which returns an impersonation token
            SafeFileHandle newToken;

            if (!LogonUser(username, domain, password, logonType, LOGON32_PROVIDER.LOGON32_PROVIDER_DEFAULT, out newToken))
            {
                Console.WriteLine($"[x] Failed to create a token for the user specified : {Marshal.GetLastWin32Error()}");
                return;
            }

            Console.WriteLine($"[*] Successfully created a token: ");

            // Duplicate the token to an impersonation token

            // Determine if we're duplicating into a primary or impersonation token
            bool isPrimary = (tokenType == "Primary");

            // Correctly assign token type
            TOKEN_TYPE tokenTypeDuplicate = isPrimary ? TOKEN_TYPE.TokenPrimary : TOKEN_TYPE.TokenImpersonation;

            // Assign impersonation level correctly (only matters for impersonation tokens)
            SECURITY_IMPERSONATION_LEVEL impersonationLevel = isPrimary ? 0 : SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation;

            // It looks easier to simply use TOKEN_ALL_ACCESS for everything even if its bad practice? maybe to be fixed later
            SafeFileHandle dupedToken;
            TOKEN_ACCESS_MASK tokenAccessRights = TOKEN_ACCESS_MASK.TOKEN_ALL_ACCESS;

            if (!DuplicateTokenEx(newToken, tokenAccessRights, new SECURITY_ATTRIBUTES(), impersonationLevel, tokenTypeDuplicate, out dupedToken))
            {
                Console.WriteLine($"[x] Failed to duplicate token : {Marshal.GetLastWin32Error()}");

                return;
            }

            // Call the helper function to print the user associated with the token
            if (!Helpers.TokenInfo(dupedToken, TOKEN_INFORMATION_CLASS.TokenUser, out TOKEN_USER tokenUser))
            {
                Console.WriteLine("[x] Failed to get token information");
                return;
            }

            // Getting the user's SID and translating it to a NTAccount
            var sid = new SecurityIdentifier(tokenUser.User.Sid);
            var user = sid.Translate(typeof(NTAccount));

            // Get the token statistics
            if (!Helpers.TokenInfo(dupedToken, TOKEN_INFORMATION_CLASS.TokenStatistics, out TOKEN_STATISTICS tokenStats))
            {
                Console.WriteLine("[x] Failed to get token statistics");
                return;
            }

            // Print the user associated with the token
            Console.WriteLine("     Impersonated User   : {0}", user);
            Console.WriteLine("     User SID            : {0}", sid);
            Console.WriteLine("     LogonType           : {0}", logonType);
            Console.WriteLine("     TokenType           : {0}", tokenStats.TokenType);
            Console.WriteLine("     Impersonation Level : {0}\r\n", tokenStats.TokenType is TOKEN_TYPE.TokenImpersonation ? tokenStats.ImpersonationLevel : "N/A");

            // Spawn a new process as the impersonated user with CreateProcessWithToken
            // If /spawn is specified, spawn a new process with the token
            if (arguments.ContainsKey("/spawn"))
            {
                // Check if /spawn exists and is not empty, otherwise default to cmd.exe
                string commandLine = arguments.TryGetValue("/spawn", out string? spawnArg) && !string.IsNullOrWhiteSpace(spawnArg)
                    ? spawnArg
                    : "C:\\Windows\\System32\\cmd.exe";

                // Create a null-terminated char array
                char[] commandLineBuffer = new char[commandLine.Length + 1];

                // Copy the command string into the array
                commandLine.AsSpan().CopyTo(commandLineBuffer);

                // Span<char> wrapping the buffer (null terminator is already there as default)
                Span<char> commandLineSpan = commandLineBuffer;

                // ----------
                // straight out stolen from RunAsCs https://github.com/antonioCoco/RunasCs/blob/master/RunasCs.cs
                // add the proper DACL on the window station and desktop that will be used
                this.stationDaclObj = new WindowStationDACL();
                string desktopName = this.stationDaclObj.AddAclToActiveWindowStation(domain, username, (int)logonType);
                // ----------

                // Define the STARTUPINFO and PROCESS_INFORMATION structs
                var startInfo = new STARTUPINFOW
                {
                    dwFlags = STARTUPINFOW_FLAGS.STARTF_USESHOWWINDOW,
                    wShowWindow = 0, // SW_HIDE
                                     //lpStartInfo.wShowWindow = 5; // SW_SHOW, required for GUI apps?
                    lpDesktop = new PWSTR(Marshal.StringToCoTaskMemUni(desktopName)),
                    cb = (uint)Marshal.SizeOf<STARTUPINFOW>()
                };

                var processInfo = new PROCESS_INFORMATION();
                string spawnMethod = "CreateProcessWithToken";

                // Set the logon flag, depending on the /netonly argument
                CREATE_PROCESS_LOGON_FLAGS logonFlags = CREATE_PROCESS_LOGON_FLAGS.LOGON_WITH_PROFILE;
                if (arguments.ContainsKey("/netonly"))
                {
                    Console.WriteLine("[*] /netonly argument specified, using LOGON_NETCREDENTIALS_ONLY for the new process\r\n");
                    logonFlags = CREATE_PROCESS_LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY;

                }
                else
                {
                    Console.WriteLine("[*] /netonly argument not specified, using LOGON_WITH_PROFILE for the new process\r\n");
                }

                // Make sure we have SeImpersonatePrivilege for the current process
                if (!Helpers.EnablePrivilege("SeImpersonatePrivilege"))
                {
                    Console.WriteLine("[x] Failed to enable SeImpersonatePrivilege");
                    return;
                }

                // Spawn a new process with the token using CreateProcessWithToken, documentation states it needs a Primary token, but it works with an Impersonation token as well??!!
                if (!CreateProcessWithToken(dupedToken, logonFlags, null, ref commandLineSpan, PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW, null, null, startInfo, out processInfo))
                {
                    Console.WriteLine($"[x] Failed to spawn the process with CreateProcessWithToken : {Marshal.GetLastWin32Error()}\n");

                    // If CreateProcessWithToken fails, try CreateProcessAsUser
                    // Enabling the required privileges for CreateProcessAsUser in our own token
                    Console.WriteLine("[!] Falling back to CreateProcessAsUser - enabling the required privileges");

                    if (!Helpers.EnablePrivilege("SeAssignPrimaryTokenPrivilege") || !Helpers.EnablePrivilege("SeIncreaseQuotaPrivilege"))
                    {
                        Console.WriteLine("\n[x] Failed to enable the required privileges for CreateProcessAsUser");
                        return;
                    }

                    // Fallback - Spawn a new process with the token using CreateProcessAsUser, documentation states it needs a Primary token, but it works with an Impersonation token as well??!!
                    spawnMethod = "CreateProcessAsUser";

                    // We redefine the span here because the previous one is not valid anymore it seems? 
                    commandLineSpan = commandLineBuffer;

                    if (!CreateProcessAsUser(newToken, null, ref commandLineSpan, null, null, false, PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW, null, null, startInfo, out processInfo))
                    {
                        Console.WriteLine($"\n[x] Failed to spawn the process with CreateProcessAsUser : {Marshal.GetLastWin32Error()}");
                        return;
                    }
                }

                // Print a success message
                Console.WriteLine("[*] Successfully spawned {0} with the duplicated token using {1}", commandLine, spawnMethod);
                Console.WriteLine("     Process ID : {0}", processInfo.dwProcessId);
                Console.WriteLine("     Thread ID  : {0}", processInfo.dwThreadId);
            }
            else
            {
                // Print a message if we dont have /spawn, this is mostly placeholder code
                Console.WriteLine("[*] Token created and duplicated, but no /spawn argument specified to spawn a process.");

                // Imperonate the token
                if (!ImpersonateLoggedOnUser(dupedToken))
                {
                    Console.WriteLine("[x] Failed to impersonate the token : {0}", Marshal.GetLastWin32Error());
                    newToken.Dispose();
                    dupedToken.Dispose();
                    return;
                }

                else
                {
                    Console.WriteLine("[*] Successfully impersonated the token.");


                    /* --Could implement code to run with the impersonated token here
                     *  
                     *  
                     * 
                    */
                }
            }

            // Cleanup
            newToken.Dispose();
            dupedToken.Dispose();
        }
    }
}