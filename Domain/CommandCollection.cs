using PointyTokenz.Commands;

namespace PointyTokenz.Domain
{
    public class CommandCollection
    {
        private readonly Dictionary<string, Func<ICommand>> _availableCommands = new Dictionary<string, Func<ICommand>>();

        // How To Add A New Command:
        //  1. Create your command class in the Commands Folder
        //      a. That class must have a CommandName static property that has the Command's name
        //              and must also Implement the ICommand interface
        //      b. Put the code that does the work into the Execute() method
        //  2. Add an entry to the _availableCommands dictionary in the Constructor below.

        public CommandCollection()
        {
            _availableCommands.Add(Adjust.CommandName, () => new Adjust());
            _availableCommands.Add(Enumerate.CommandName, () => new Enumerate());
            _availableCommands.Add(Make.CommandName, () => new Make());
            _availableCommands.Add(Help.CommandName, () => new Help());
            _availableCommands.Add(Steal.CommandName, () => new Steal());
            _availableCommands.Add(RunAs.CommandName, () => new RunAs());
            _availableCommands.Add(RunAsAdmin.CommandName, () => new RunAsAdmin());
            _availableCommands.Add(Revert.CommandName, () => new Revert());
        }

        public bool ExecuteCommand(string commandName, Dictionary<string, string> arguments)
        {
            bool commandWasFound;

            if (string.IsNullOrEmpty(commandName) || _availableCommands.ContainsKey(commandName) == false)
                commandWasFound = false;
            else
            {
                // Create the command object 
                var command = _availableCommands[commandName].Invoke();

                // and execute it with the arguments from the command line
                command.Execute(arguments);

                commandWasFound = true;
            }

            return commandWasFound;
        }
    }
}
