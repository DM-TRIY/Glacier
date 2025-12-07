using System;
using System.Collections.Generic;
using System.Text;

namespace Glacier.Core;

public class ScanResult
{
    public string FilePath { get; set; } = string.Empty;

    public long SizeBytes { get; set; }

    public string Extension { get; set; } = string.Empty;

    public string SHA256 { get; set; } = string.Empty;

    public List<string> YaraMatches { get; set; } = new();

    public RiskLevel Level { get; set; }

    public int SuspiciousScore { get; set; }

    public List<string> Reasons { get; set; } = new();
}
