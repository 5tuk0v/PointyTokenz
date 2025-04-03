

namespace PointyTokenz.Commands
{
    public interface ICommand
    {
        void Execute(Dictionary<string, string> arguments);
    }
}
