using PointyTokenz.Domain;
using System.Text;

using static Windows.Win32.PInvoke;


namespace PointyTokenz;

internal static unsafe class Program
{
    public static void Main(string[] args)
    {
        // try to parse the command line arguments, show usage on failure and then bail
        var parsed = ArgumentParser.Parse(args);
        if (parsed.ParsedOk == false)
        {
            Info.ShowLogo();
            Info.ShowUsage();
            return;
        }

        var commandName = args.Length != 0 ? args[0] : "";

        MainExecute(commandName, parsed.Arguments);
    }

    private static void MainExecute(string commandName, Dictionary<string, string> parsedArgs)
    {
        // main execution logic

        Info.ShowLogo();

        try
        {
            // print unicode char properly if there's a console
            if (IsConsolePresent()) Console.OutputEncoding = Encoding.UTF8;

            var commandFound = new CommandCollection().ExecuteCommand(commandName, parsedArgs);

            // show the usage if no commands were found for the command name
            if (commandFound == false)
                Info.ShowUsage();
        }
        catch (Exception e)
        {
            Console.WriteLine("\r\n[!] Unhandled exception:\r\n");
            Console.WriteLine($"Exception Type: {e.GetType().Name}");
            Console.WriteLine($"Message: {e.Message}");
            Console.WriteLine($"Stack Trace: {e.StackTrace}");
        }
    }

    public static string MainString(string command)
    {
        // helper that executes an input string command and returns results as a string
        //  useful for PSRemoting execution

        string[] args = command.Split();

        var parsed = ArgumentParser.Parse(args);
        if (parsed.ParsedOk == false)
        {
            Info.ShowLogo();
            Info.ShowUsage();
            return "Error parsing arguments: ${command}";
        }

        var commandName = args.Length != 0 ? args[0] : "";

        TextWriter realStdOut = Console.Out;
        TextWriter realStdErr = Console.Error;
        TextWriter stdOutWriter = new StringWriter();
        TextWriter stdErrWriter = new StringWriter();
        Console.SetOut(stdOutWriter);
        Console.SetError(stdErrWriter);

        MainExecute(commandName, parsed.Arguments);

        Console.Out.Flush();
        Console.Error.Flush();
        Console.SetOut(realStdOut);
        Console.SetError(realStdErr);

        string output = "";
        output += stdOutWriter.ToString();
        output += stdErrWriter.ToString();

        return output;
    }

    private static bool IsConsolePresent()
    {
        return GetConsoleWindow() != IntPtr.Zero;
    }
}