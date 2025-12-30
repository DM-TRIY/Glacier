using System.Reflection;
using dnYara;

namespace Glacier.Core;

public class YaraEngine : IDisposable
{
    private readonly YaraContext _ctx;
    private CompiledRules? _rules;

    public bool IsReady { get; private set; }

    public YaraEngine()
    {
        _ctx = new YaraContext();

        using var compiler = new Compiler();

        var assembly = Assembly.GetExecutingAssembly();
        var resourceNames = assembly.GetManifestResourceNames()
            .Where(n => n.EndsWith(".yar", StringComparison.OrdinalIgnoreCase));

        foreach (var resName in resourceNames)
        {
            using var stream = assembly.GetManifestResourceStream(resName);
            using var reader = new StreamReader(stream!);
            string ruleText = reader.ReadToEnd();

            compiler.AddRuleString(ruleText);
        }

        _rules = compiler.Compile();
        IsReady = _rules != null;
    }

    public IEnumerable<string> Scan(string filePath)
    {
        if (!IsReady || _rules == null)
            return Enumerable.Empty<string>();

        if (!File.Exists(filePath))
            return Enumerable.Empty<string>();

        var scanner = new Scanner();

        List<dnYara.ScanResult> results = scanner.ScanFile(filePath, _rules);

        return results
            .Select(r => r.MatchingRule.Identifier)
            .Distinct()
            .ToList();
    }

    public void Dispose()
    {
        _rules?.Dispose();
        _ctx?.Dispose();
    }
}
