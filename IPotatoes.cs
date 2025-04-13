namespace TotalPotato
{
    internal interface IPotatoes
    {
        string Name { get; }
        string Description { get; }

        bool IsApplicable();
        bool Execute(string command, string rev_host, int rev_port);
    }
}
