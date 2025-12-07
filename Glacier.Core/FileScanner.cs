using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Glacier.Core;

public class FileScanner
{
    public IEnumerable<ScanResult> ScanDirectory(string rootPath)
    {
        if (!Directory.Exists(rootPath))
            throw new DirectoryNotFoundException($"Directory not found: {rootPath}");

        var results = new List<ScanResult>();
        ScanRecursive(rootPath, results);
        return results;
    }


    private void ScanRecursive(string currentPath, List<ScanResult> results)
    {
        foreach (var file in Directory.EnumerateFiles(currentPath))
        {
            var result = AnalyzeFile(file);
            results.Add(result);
        }

        foreach (var dir in Directory.EnumerateDirectories(currentPath))
        {
            try
            {
                ScanRecursive(dir, results);
            }
            catch
            {
                // На будущее — логировать отказ доступа
            }
        }
    }


    private readonly YaraEngine? _yara;

    public FileScanner(YaraEngine? yaraEngine = null)
    {
        _yara = yaraEngine;
    }

    private ScanResult AnalyzeFile(string filePath)
    {
        var fileInfo = new FileInfo(filePath);

        var result = new ScanResult
        {
            FilePath = filePath,
            SizeBytes = fileInfo.Length,
            Extension = fileInfo.Extension.ToLowerInvariant(),
            SHA256 = CalculateSHA256(filePath)
        };

        int score = 0;

        // Простая "эвристика" — не тупая, но минимальная
        if (result.Extension is ".exe" or ".dll" or ".bat" or ".cmd" or ".ps1")
        {
            score += 50;
            result.Reasons.Add("Executable file extension");
        }

        if (score > 0 && result.SizeBytes is > 0 and < 50 * 1024)
        {
            score += 20;
            result.Reasons.Add("Very small executable (possible loader/dropper)");
        }

        if (result.Extension is ".ps1" or ".js" or ".vbs")
        {
            score += 5;
            result.Reasons.Add("Script file detected");
        }

        var p = filePath.ToLowerInvariant();
        if (p.Contains("temp") || p.Contains("downloads") || p.Contains("appdata\\local"))
        {
            score += 10;
            result.Reasons.Add("Located in unusual directory");
        }

        // --- YARA SCAN ---
        if (_yara != null && _yara.IsReady)
        {
            try
            {
                var matches = _yara.Scan(filePath).ToList();
                result.YaraMatches.AddRange(matches);

                if (matches.Count > 0)
                {
                    score += 100; // буст вейта
                    result.Reasons.Add("YARA signature match");
                }
            }
            catch (Exception ex)
            {
                // Потом можно логировать
            }
        }

        result.SuspiciousScore = score;
        result.Level = GetRiskLevel(score);
        return result;
    }


    private static string CalculateSHA256(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hashBytes = sha256.ComputeHash(stream);
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
    }


    public static RiskLevel GetRiskLevel(int score)
    {
        if (score >= 60)
            return RiskLevel.High;

        if (score >= 20)
            return RiskLevel.Medium;

        return RiskLevel.Low;
    }

}
