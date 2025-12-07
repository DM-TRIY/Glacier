using Glacier.Core;
using Glacier.CLI;

Console.OutputEncoding = System.Text.Encoding.UTF8;

Console.WriteLine(ConsoleStyles.Red(
@"  ooooooo8  ooooo            o        oooooooo8 ooooo ooooooooooo oooooooooo  
o888    88   888            888     o888     88  888   888    88   888    888 
888    oooo  888           8  88    888          888   888ooo8     888oooo88  
888o    88   888      o   8oooo88   888o     oo  888   888    oo   888  88o   
 888ooo888  o888ooooo88 o88o  o888o  888oooo88  o888o o888ooo8888 o888o  88o8 
"));
Console.WriteLine();
Console.WriteLine(ConsoleStyles.Gray("Intellegent Cybersecurity Solution\n"));
Console.Write(ConsoleStyles.Gray("BUILD CODENAME: "));
Console.Write(ConsoleStyles.Cyan("WATCHDOG\n"));
Console.WriteLine(ConsoleStyles.Gray("\n2025\n"));

Console.Write("Введите путь к папке для анализа: ");
var path = Console.ReadLine();

if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
{
    Console.WriteLine("Путь не найден.");
    return;
}

var yara = new YaraEngine(); // путь к правилам
var scanner = new FileScanner(yara);
var results = scanner.ScanDirectory(path);

var ordered = results
    .OrderByDescending(r => r.SuspiciousScore)
    .ThenByDescending(r => r.SizeBytes)
    .ToList();

Console.WriteLine();
Console.WriteLine($"Найдено файлов: {ordered.Count}");
Console.WriteLine();

int high = ordered.Count(r => r.Level == RiskLevel.High);
int med = ordered.Count(r => r.Level == RiskLevel.Medium);
int low = ordered.Count(r => r.Level == RiskLevel.Low);

foreach (var r in ordered)
{
    Console.WriteLine("----------------------------------------");
    Console.WriteLine($"Уровень риска: {ConsoleStyles.ColorizeRisk(r.Level)}");
    Console.WriteLine(r.FilePath);
    Console.WriteLine($"Размер: {r.SizeBytes} байт");
    Console.WriteLine($"Расширение: {r.Extension}");
    Console.WriteLine($"SHA256: {r.SHA256}");
    Console.WriteLine($"Score: {r.SuspiciousScore}");

    if (r.Reasons.Count > 0)
    {
        Console.WriteLine("Причины:");
        foreach (var reason in r.Reasons)
            Console.WriteLine("  - " + reason);
    }
    else
    {
        Console.WriteLine("Причины: нет");
    }

    if (r.YaraMatches.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine(ConsoleStyles.Red("YARA DETECTIONS:"));
        foreach (var match in r.YaraMatches)
            Console.WriteLine("  - " + match);
    }
}

Console.WriteLine("----------------------------------------");
Console.WriteLine();
Console.WriteLine("=== HEUR Analysis results ===");
Console.WriteLine($"High: {ConsoleStyles.Red(high.ToString())}");
Console.WriteLine($"Medium: {ConsoleStyles.Yellow(med.ToString())}");
Console.WriteLine($"Low: {ConsoleStyles.Gray(low.ToString())}");
Console.WriteLine("========================");
Console.WriteLine();

Console.WriteLine();
Console.WriteLine("Готово!");
Console.ReadLine();
