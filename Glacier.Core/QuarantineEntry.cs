namespace Glacier.Core.Quarantine;

public enum QuarantineState
{
    Isolated,
    Restored
}

public class QuarantineEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString();

    public string OriginalPath { get; set; } = string.Empty;
    public string OriginalName { get; set; } = string.Empty;

    public string QuarantinePath { get; set; } = string.Empty;

    public string SHA256 { get; set; } = string.Empty;
    public long SizeBytes { get; set; }

    public RiskLevel Risk { get; set; }
    public int Score { get; set; }

    public List<string> YaraMatches { get; set; } = new();

    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public QuarantineState State { get; set; } = QuarantineState.Isolated;
}
