
using static Windows.Win32.PInvoke;

namespace PointyTokenz.Commands
{
    public class Revert : ICommand
    {
        public static string CommandName => "revert";

        public unsafe void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Command: revert\r\n");

            // Print the help message if requested
            if (arguments.ContainsKey("/help"))
            {
                Console.WriteLine("Action:");
                Console.WriteLine(" Revert to the process token. Used to drop impersonation from \"steal\" or \"make\".");
                return;
            }

            // Call RevertToSelf to revert to the process token
            if (RevertToSelf())
            {
                Console.WriteLine("[+] Successfully reverted to self.");
            }
            else
            {
                Console.WriteLine("[x] Failed to revert to self.");
            }
        }
    }
}
