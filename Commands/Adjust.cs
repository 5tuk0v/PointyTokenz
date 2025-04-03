using System.Runtime.InteropServices;
using static Windows.Win32.PInvoke;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.System.Threading;

namespace PointyTokenz.Commands
{
    public class Adjust : ICommand
    {
        public static string CommandName => "adjust";
        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Command: adjust\r\n");

            string privilege = "";
            string action = "";
            string pidStr = "";

            // Parse the command line arguments
            // If /help is specified, show the help message
            if (arguments.ContainsKey("/help"))
            {
                Console.WriteLine("Action:");
                Console.WriteLine(" Adjust the privileges of the primary token of a target process.\r\n");

                Console.WriteLine("Requirements:");
                Console.WriteLine(" The privilege must already be assigned to the target process.\r\n");

                Console.WriteLine("Options:");
                Console.WriteLine(" /privilege:<privilege> - The name of the privilege to adjust. (required)");
                Console.WriteLine(" /action:<action>       - The action to perform on the privilege. (required)");
                Console.WriteLine(" /pid:<pid>             - The process ID to adjust the token of. (required)");
                Console.WriteLine(" /help                  - Show this help message.\r\n");

                Console.WriteLine("Supported actions:");
                Console.WriteLine(" enable  - Enable the privilege");
                Console.WriteLine(" disable - Disable the privilege");
                Console.WriteLine(" remove  - Remove the privilege");

                return;
            }

            if (arguments.ContainsKey("/privilege"))
            {
                privilege = arguments["/privilege"];
            }
            if (arguments.ContainsKey("/action"))
            {
                action = arguments["/action"];
            }
            if (arguments.ContainsKey("/pid"))
            {
                pidStr = arguments["/pid"];
            }

            // Convert the PID to an integer
            if (!int.TryParse(pidStr, out int pid))
            {
                Console.WriteLine("[x] Failed to parse the PID");
                return;
            }

            HandleAdjustAction(arguments, privilege, action, pid);
        }

        private static unsafe void HandleAdjustAction(Dictionary<string, string> arguments, string privilege, string action, int pid)
        {
            // Explicit validation of all required parameters before use
            if (string.IsNullOrEmpty(privilege))
            {
                Console.WriteLine("[x] Missing or empty required parameter: /privilege");
                Environment.Exit(1);
            }

            if (string.IsNullOrEmpty(action))
            {
                Console.WriteLine("[x] Missing or empty required parameter: /action");
                Environment.Exit(1);
            }

            if (string.IsNullOrEmpty(pid.ToString()))
            {
                Console.WriteLine("[x] Missing or empty required parameter: /pid");
                Environment.Exit(1);
            }

            // Get and validate the PID
            var hProcess = OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
            if (hProcess.IsNull)
            {
                Console.WriteLine($"[x] Failed to open process {pid} : {Marshal.GetLastWin32Error()}");
                return;
            }

            // Lookup the privilege LUID
            LUID privilegeLuid;
            if (!LookupPrivilegeValue(null, privilege, out privilegeLuid))
            {
                Console.WriteLine($"[x] Failed to lookup privilege '{privilege}' : {Marshal.GetLastWin32Error()}");
                CloseHandle(hProcess);
                return;
            }

            // Open the process token
            HANDLE hToken;
            if (!OpenProcessToken(hProcess, TOKEN_ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES, &hToken))
            {
                Console.WriteLine($"[x] Failed to open process token : {Marshal.GetLastWin32Error()}");
                CloseHandle(hProcess);
                return;
            }

            // Prepare the privilege adjustment struct
            var newPrivilege = new TOKEN_PRIVILEGES();
            newPrivilege.PrivilegeCount = 1;
            newPrivilege.Privileges[0].Luid = privilegeLuid;

            // Set the privilege state based on the action
            newPrivilege.Privileges[0].Attributes = action.ToLower() switch
            {
                "enable" => TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED,
                "disable" => 0,
                "remove" => TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_REMOVED,
                _ => throw new ArgumentException("[!] Invalid state. Valid states are: enable (SE_PRIVILEGE_ENABLED), disable (0), remove (SE_PRIVILEGE_REMOVED)"),
            };

            // Apply the token privilege change
            if (!AdjustTokenPrivileges(hToken, false, &newPrivilege, (uint)Marshal.SizeOf(newPrivilege), null, null))
            {
                Console.WriteLine($"[x] Failed to adjust token privileges : {Marshal.GetLastWin32Error()}");
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return;
            }

            // Check if the change was successful
            int lastError = Marshal.GetLastWin32Error();
            if (lastError == 0)
            {
                Console.WriteLine($"[*] Successfully {action}d privilege '{privilege}' for process {pid}.");
            }
            else if (lastError == (int)WIN32_ERROR.ERROR_NOT_ALL_ASSIGNED)
            {
                Console.WriteLine($"[!] Warning: The requested privilege '{privilege}' was not assigned to process {pid} : {Marshal.GetLastWin32Error()}");
            }
            else
            {
                Console.WriteLine($"[x] Failed to adjust token privileges : {Marshal.GetLastWin32Error()}");
            }

            // Cleanup handles
            CloseHandle(hToken);
            CloseHandle(hProcess);
        }
    }
}
