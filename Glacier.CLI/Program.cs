using Glacier.CLI;
using Glacier.Core;
using Glacier.Core.Quarantine;

Console.OutputEncoding = System.Text.Encoding.UTF8;

while (true)
{
    Console.Clear();
    ShowArt();

    Console.WriteLine(ConsoleStyles.Gray("Выберите действие:"));
    Console.WriteLine("1 - Одноразовый анализ");
    Console.WriteLine("2 - Realtime мониторинг");
    Console.WriteLine("3 - Управление карантином");
    Console.WriteLine("0 - Выход");
    Console.Write(">> ");

    var choice = Console.ReadLine();

    switch (choice)
    {
        case "1":
            RunSingleScan();
            break;

        case "2":
            RunRealtime();
            break;

        case "3":
            RunQuarantineMenu();
            break;

        case "0":
            Console.WriteLine("Выход...");
            return;

        default:
            Console.WriteLine("Неверный выбор");
            Pause();
            break;
    }
}
static void RunSingleScan()
{
    Console.Clear();
    Console.Write("Введите путь к директории для анализа: ");
    var path = Console.ReadLine();

    if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
    {
        Console.WriteLine("Путь не найден.");
        Pause();
        return;
    }

    var yara = new YaraEngine();
    var scanner = new FileScanner(yara);
    var quarantine = new QuarantineManager(
        Path.Combine(Environment.CurrentDirectory, "quarantine"),
        new UserModeFileIsolator()
    );

    var results = scanner.ScanDirectory(path);

    var ordered = results
        .OrderByDescending(r => r.SuspiciousScore)
        .ThenByDescending(r => r.SizeBytes)
        .ToList();

    Console.WriteLine();
    Console.WriteLine($"Найдено файлов: {ordered.Count}");
    Console.WriteLine();

    foreach (var r in ordered)
    {
        Console.WriteLine("----------------------------------------");
        Console.WriteLine($"Уровень риска: {ConsoleStyles.ColorizeRisk(r.Level)}");
        Console.WriteLine(r.FilePath);
        Console.WriteLine($"Score: {r.SuspiciousScore}");

        if (r.YaraMatches.Count > 0)
        {
            Console.WriteLine(ConsoleStyles.Red("YARA DETECTIONS:"));
            foreach (var match in r.YaraMatches)
                Console.WriteLine("  - " + match);
        }

        if (r.Level == RiskLevel.High)
        {
            Console.WriteLine(ConsoleStyles.Red("AUTO-QUARANTINE"));

            try
            {
                var entry = quarantine.Isolate(r);
                Console.WriteLine($"[QUARANTINED] ID: {entry.Id}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FAILED] {ex.Message}");
            }
        }
    }

    Pause();
}

static void RunRealtime()
{
    var yara = new YaraEngine();
    var scanner = new FileScanner(yara);
    var quarantine = new QuarantineManager(
        Path.Combine(Environment.CurrentDirectory, "quarantine"),
        new UserModeFileIsolator()
    );

    Console.Clear();
    Console.Write("Введите путь к директории для мониторинга: ");
    var path = Console.ReadLine();

    if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
    {
        Console.WriteLine("Путь не найден.");
        Pause();
        return;
    }

    Console.WriteLine();
    Console.WriteLine("Запуск realtime мониторинга...");
    var monitor = new RealtimeMonitor(path, scanner);
    monitor.Start();

    Console.WriteLine("Нажмите Enter для остановки...");
    Console.ReadLine();

    monitor.Stop();
    return;
}

static void RunQuarantineMenu()
{
    var quarantine = new QuarantineManager(
        Path.Combine(Environment.CurrentDirectory, "quarantine"),
        new UserModeFileIsolator()
    );

    while (true)
    {
        Console.Clear();
        ShowArt();

        Console.WriteLine("=== Управление карантином ===");
        Console.WriteLine("1 - Список файлов");
        Console.WriteLine("2 - Восстановить файл");
        Console.WriteLine("0 - Назад");
        Console.Write(">> ");

        var choice = Console.ReadLine();

        switch (choice)
        {
            case "1":
                ShowQuarantineList(quarantine);
                break;

            case "2":
                RestoreFromQuarantine(quarantine);
                break;

            case "0":
                return;

            default:
                Console.WriteLine("Неверный выбор");
                Pause();
                break;
        }
    }
}

static void ShowQuarantineList(QuarantineManager quarantine)
{
    Console.Clear();
    ShowArt();

    var entries = quarantine.List();

    if (!entries.Any())
    {
        Console.WriteLine("Карантин пуст.");
        Pause();
        return;
    }

    foreach (var e in entries)
    {
        Console.WriteLine("----------------------------------------");
        Console.WriteLine($"ID: {e.Id}");
        Console.WriteLine($"Исходный путь: {e.OriginalPath}");
        Console.WriteLine($"Risk: {e.Risk}");
        Console.WriteLine($"Score: {e.Score}");
        Console.WriteLine($"Дата: {e.TimestampUtc}");
    }

    Console.WriteLine("----------------------------------------");
    Pause();
}

static void RestoreFromQuarantine(QuarantineManager quarantine)
{
    Console.Clear();
    ShowArt();

    Console.Write("Введите ID файла для восстановления: ");
    var id = Console.ReadLine();

    if (string.IsNullOrWhiteSpace(id))
    {
        Console.WriteLine("ID пустой.");
        Pause();
        return;
    }

    try
    {
        quarantine.Restore(id);
        Console.WriteLine("Файл восстановлен.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Ошибка: {ex.Message}");
    }

    Pause();
}


static void ShowArt()
{
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
    Console.Write(ConsoleStyles.Cyan("KNIGHT\n"));
    Console.WriteLine(ConsoleStyles.Gray("\n2025\n"));
}

static void Pause()
{
    Console.WriteLine();
    Console.WriteLine("Нажмите Enter...");
    Console.ReadLine();
}