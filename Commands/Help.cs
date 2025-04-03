using PointyTokenz.Domain;

namespace PointyTokenz.Commands
{
    public class Help : ICommand
    {
        public static string CommandName => "help";
        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: help\r\n");
        
            Info.ShowUsage();
        }
    }
}
