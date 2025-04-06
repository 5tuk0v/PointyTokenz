/* This code is from Rubeus
Rubeus is provided under the 3-clause BSD license below.

*************************************************************

Copyright (c) 2018, Will Schroeder
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    The names of its contributors may not be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.*/
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