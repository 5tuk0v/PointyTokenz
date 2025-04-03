using System.Runtime.InteropServices;
using Windows.Win32.System.Threading;

using static Windows.Win32.PInvoke;

namespace PointyTokenz.Commands
{
    public class RunAs : ICommand
    {
        public static string CommandName => "runas";

        public unsafe void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Command: runas\r\n");

            // Check if the /help argument is present
            if (arguments.ContainsKey("/help"))
            {
                Console.WriteLine("Action:");
                Console.WriteLine(" Run a command as another user with plaintext credentials using CreateProcessWithLogon.\r\n");

                Console.WriteLine("Requirements:");
                Console.WriteLine(" The supplied user must have the Log On Locally permission.\r\n");

                Console.WriteLine("Purpose:");
                Console.WriteLine(" This is useful for running a command as another user without having to interactively log in.");
                Console.WriteLine(" This can also be used to spawn a process using LOGON_NETCREDENTIALS_ONLY to impersonate the user only for network access. (with /netonly)\r\n");

                Console.WriteLine("Options:");
                Console.WriteLine(" /username:<username>  - The username to run the command as. (required)");
                Console.WriteLine(" /password:<password>  - The password of the user. (required)");
                Console.WriteLine(" /domain:<domain>      - The domain of the user. (optional, defaults to machine name)");
                Console.WriteLine(" /command:<command>    - The command to run as the user. (required)");
                Console.WriteLine(" /netonly              - Run the command with network credentials only. (optional - defaults to LOGON_WITH_PROFILE)");
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

            // Check if the /command argument is present
            if (arguments.ContainsKey("/command") == false)
            {
                Console.WriteLine("[x] The /command argument is required.");
                return;
            }

            // Check if the /netonly argument is present
            bool netOnly = arguments.ContainsKey("/netonly");

            // Parse the username from the arguments
            string username = arguments["/username"];

            // Parse the domain from the arguments if present
            string domain = Environment.MachineName;
            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
            }

            // Parse the password from the arguments
            string password = arguments["/password"];

            // Ensure there's at least a default program
            string programWithArgs = arguments["/command"]?.Trim() ?? "";

            if (string.IsNullOrWhiteSpace(programWithArgs))
            {
                programWithArgs = "C:\\Windows\\System32\\cmd.exe";
            }

            // If the first part is an executable path with spaces but not quoted, quote it
            if (!programWithArgs.StartsWith("\""))
            {
                int firstSpaceIndex = programWithArgs.IndexOf(' ');
                if (firstSpaceIndex != -1)
                {
                    string executablePath = programWithArgs.Substring(0, firstSpaceIndex);
                    string remainingArgs = programWithArgs.Substring(firstSpaceIndex);
                    programWithArgs = $"\"{executablePath}\"{remainingArgs}";
                }
            }

            // Convert the string to a mutable char array as CreateProcessWithTokenW requires a mutable string
            char[] commandLineBuffer = (programWithArgs + "\0").ToCharArray();
            Span<char> commandLine = commandLineBuffer; // Create Span<char> from the array

            // Define the STARTUPINFO and PROCESS_INFORMATION structs
            var lpStartInfo = new STARTUPINFOW
            {
                dwFlags = STARTUPINFOW_FLAGS.STARTF_USESHOWWINDOW,
                wShowWindow = 0, // SW_HIDE
                cb = (uint)Marshal.SizeOf<STARTUPINFOW>()
            };

            var lpProcessInfo = new PROCESS_INFORMATION();

            // if /netonly is specified, use LOGON_NETCREDENTIALS_ONLY
            CREATE_PROCESS_LOGON_FLAGS logonType = CREATE_PROCESS_LOGON_FLAGS.LOGON_WITH_PROFILE; // Default logon flag
            if (netOnly)
            {
                // If domain is not specified, use the computer name, otherwise use the specified domain. The API call fails without a domain
                if (string.IsNullOrEmpty(domain))
                {
                    domain = Environment.MachineName;
                }
                Console.WriteLine("[*] /netonly argument specified, using LOGON_NETCREDENTIALS_ONLY\r\n");
                logonType = CREATE_PROCESS_LOGON_FLAGS.LOGON_NETCREDENTIALS_ONLY;
            }

            // Spawn a new hidden process with plaintext credentials using CreateProcessWithLogon
            if (!CreateProcessWithLogon(username, domain, password, logonType, null, ref commandLine, PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW, null, null, lpStartInfo, out lpProcessInfo))
            {
                Console.WriteLine($"[x] Failed to spawn the process with CreateProcessWithLogon : {Marshal.GetLastWin32Error()}");
                return;
            }

            // Print a success message
            Console.WriteLine($"[*] Successfully spawned {programWithArgs} as {domain}\\{username}");
            Console.WriteLine("Process ID : {0}", lpProcessInfo.dwProcessId);
            Console.WriteLine("Thread ID  : {0}", lpProcessInfo.dwThreadId);
            Console.WriteLine("Logon type : {0}\r\n", logonType);
        }
    }
}
