using Glacier.Core;

namespace Glacier.CLI;

public static class ConsoleStyles
{
    private const string Reset = "\u001b[0m";

    public static string Red(string text) =>
        $"\u001b[31m{text}{Reset}";

    public static string Yellow(string text) =>
        $"\u001b[33m{text}{Reset}";

    public static string Green(string text) =>
        $"\u001b[32m{text}{Reset}";

    public static string Cyan(string text) =>
        $"\u001b[36m{text}{Reset}";

    public static string Magenta(string text) =>
        $"\u001b[35m{text}{Reset}";

    public static string White(string text) =>
        $"\u001b[37m{text}{Reset}";

    public static string Gray(string text) =>
        $"\u001b[90m{text}{Reset}";

    public static string ColorizeRisk(RiskLevel level)
    {
        return level switch
        {
            RiskLevel.High => Red("HIGH"),

            RiskLevel.Medium => Yellow("MEDIUM"),

            _ => Gray("LOW")
        };
    }

}
