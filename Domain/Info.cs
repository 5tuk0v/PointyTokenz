
namespace PointyTokenz.Domain
{
    public static class Info
    {
        public static void ShowLogo()
        {
            Console.WriteLine(@"
  _____      _       _      _______    _                  
 |  __ \    (_)     | |    |__   __|  | |                 
 | |__) |__  _ _ __ | |_ _   _| | ___ | | _____ _ __  ____
 |  ___/ _ \| | '_ \| __| | | | |/ _ \| |/ / _ \ '_ \|_  /
 | |  | (_) | | | | | |_| |_| | | (_) |   <  __/ | | |/ / 
 |_|   \___/|_|_| |_|\__|\__, |_|\___/|_|\_\___|_| |_/___|
                          __/ |                           
                         |___/                            

                    Version 0.0.1
");
        }

        public static void ShowUsage()
        {
            Console.WriteLine();
            Console.WriteLine("PointyTokenz.exe - Manage and manipulate process tokens.\r\n");

            Console.WriteLine("Available Commands:");
            Console.WriteLine("  help       - Show this help message.");
            Console.WriteLine("  make       - Create a primary access token and duplicate it to an impersonation token, then impersonate it or spawn a process with it.");
            Console.WriteLine("  enum       - Enumerate the privileges of a target process token.");
            Console.WriteLine("  adjust     - Adjust the privileges of a process token.");
            Console.WriteLine("  steal      - Steal and duplicate the primary token of a target process, then impersonate it or spawn a process with it");
            Console.WriteLine("  runas      - Run a command as another user using plaintext credentials.");
            Console.WriteLine("  runasadmin - Run a command as an administrator with elevated privileges using plaintext credentials (UAC Bypass).");
            Console.WriteLine("  revert     - Revert to the process token. Used to drop impersonation from \"steal\" or \"make\".\r\n");

            Console.WriteLine("Usage:");
            Console.WriteLine("  PointyTokenz.exe <command> [options]");
            Console.WriteLine("  PointyTokenz.exe <command> /help (for detailed command usage)\r\n");

            Console.WriteLine("Examples:");
            Console.WriteLine("  PointyTokenz.exe help");
            Console.WriteLine("  PointyTokenz.exe adjust /help");
            Console.WriteLine("  PointyTokenz.exe adjust /privilege:SeDebugPrivilege /action:enable /pid:1234\r\n");
        }
    }
}
