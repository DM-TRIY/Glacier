using System.Text.Json;

namespace Glacier.Core.Quarantine;

public class QuarantineManager
{
    private readonly string _rootPath;
    private readonly string _indexPath;
    private readonly IFileIsolator _isolator;

    private readonly Dictionary<string, QuarantineEntry> _entries = new();

    public QuarantineManager(string rootPath, IFileIsolator isolator)
    {
        _rootPath = rootPath;
        _isolator = isolator;

        _indexPath = Path.Combine(_rootPath, "index.json");
        Directory.CreateDirectory(_rootPath);

        LoadIndex();
    }

    public QuarantineEntry Isolate(ScanResult scan)
    {
        var entry = new QuarantineEntry
        {
            OriginalPath = scan.FilePath,
            OriginalName = Path.GetFileName(scan.FilePath),
            SHA256 = scan.SHA256,
            SizeBytes = scan.SizeBytes,
            Risk = scan.Level,
            Score = scan.SuspiciousScore,
            YaraMatches = scan.YaraMatches.ToList()
        };

        entry.QuarantinePath = Path.Combine(
            _rootPath,
            $"{entry.Id}.qf"
        );

        _isolator.Isolate(scan.FilePath, entry.QuarantinePath);

        _entries[entry.Id] = entry;
        SaveIndex();

        return entry;
    }

    public void Restore(string id)
    {
        if (!_entries.TryGetValue(id, out var entry))
            throw new InvalidOperationException("Quarantine entry not found");

        _isolator.Restore(entry.QuarantinePath, entry.OriginalPath);

        entry.State = QuarantineState.Restored;
        SaveIndex();
    }

    public IReadOnlyCollection<QuarantineEntry> List()
        => _entries.Values;

    private void SaveIndex()
    {
        var json = JsonSerializer.Serialize(
            _entries.Values,
            new JsonSerializerOptions { WriteIndented = true }
        );

        File.WriteAllText(_indexPath, json);
    }

    private void LoadIndex()
    {
        if (!File.Exists(_indexPath))
            return;

        var json = File.ReadAllText(_indexPath);
        var items = JsonSerializer.Deserialize<List<QuarantineEntry>>(json);

        if (items == null)
            return;

        foreach (var entry in items)
            _entries[entry.Id] = entry;
    }
}
