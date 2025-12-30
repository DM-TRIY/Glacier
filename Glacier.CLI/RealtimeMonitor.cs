using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Glacier.Core;

namespace Glacier.CLI
{
    public class RealtimeMonitor : IDisposable
    {
        private readonly FileScanner _scanner;
        private readonly FileSystemWatcher _watcher;

        private readonly ConcurrentQueue<string> _queue = new();
        private readonly ConcurrentDictionary<string, DateTime> _lastEvent = new();

        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(4);

        private bool _running = false;

        public RealtimeMonitor(string path, FileScanner scanner)
        {
            if (!Directory.Exists(path))
                throw new DirectoryNotFoundException($"Directory not found: {path}");

            _scanner = scanner;

            _watcher = new FileSystemWatcher(path)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName |
                               NotifyFilters.LastWrite |
                               NotifyFilters.Size |
                               NotifyFilters.CreationTime,
                Filter = "*.*"
            };

            _watcher.Created += OnFsEvent;
            _watcher.Changed += OnFsEvent;
            _watcher.Renamed += OnRenamed;
        }

        public void Start()
        {
            _running = true;
            _watcher.EnableRaisingEvents = true;

            Task.Run(ProcessQueue);
        }

        public void Stop()
        {
            _running = false;
            _watcher.EnableRaisingEvents = false;
        }

        private void OnFsEvent(object sender, FileSystemEventArgs e)
        {
            // На этом этапе File.Exists почти всегда FALSE (файл ещё не создан полностью).
            // Поэтому НЕ ДЕЛАЕМ File.Exists здесь!

            string ext = Path.GetExtension(e.FullPath).ToLowerInvariant();

            // Разумный минимум игнора (исключаем только мусор)
            if (ext is ".log" or ".tmp" or ".sqlite" or ".db")
                return;

            var now = DateTime.UtcNow;
            var last = _lastEvent.GetOrAdd(e.FullPath, now);

            // увеличили debounce до 500ms — устойчивее к реальным сценариям
            if ((now - last).TotalMilliseconds < 500)
            {
                _lastEvent[e.FullPath] = now;
                return;
            }

            _lastEvent[e.FullPath] = now;

            _queue.Enqueue(e.FullPath);
        }

        private void OnRenamed(object sender, RenamedEventArgs e)
        {
            // Переименование почти всегда важнее обычного изменения
            _queue.Enqueue(e.FullPath);
        }

        private async Task ProcessQueue()
        {
            while (_running)
            {
                if (!_queue.TryDequeue(out var path))
                {
                    await Task.Delay(50);
                    continue;
                }

                await _semaphore.WaitAsync();

                _ = Task.Run(async () =>
                {
                    try
                    {
                        // ДАЁМ ФАЙЛУ ДОЖИТЬ ДО РЕАЛЬНОГО СОСТОЯНИЯ
                        await Task.Delay(200);

                        if (!File.Exists(path))
                            return;

                        var result = _scanner.ScanFile(path);

                        if (IsInteresting(result))
                            PrintResult(result, path);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[RT ERROR] {ex.Message}");
                    }
                    finally
                    {
                        _semaphore.Release();
                    }
                });
            }
        }

        private static bool IsInteresting(ScanResult result)
        {
            return result.Level == RiskLevel.Medium
                   || result.Level == RiskLevel.High
                   || result.YaraMatches.Count > 0;
        }

        private void PrintResult(ScanResult result, string path)
        {
            Console.WriteLine();
            Console.WriteLine("----------------------------------------");
            Console.WriteLine($"[RT] {path}");
            Console.WriteLine($"Уровень риска: {ConsoleStyles.ColorizeRisk(result.Level)}");
            Console.WriteLine($"Размер: {result.SizeBytes} байт");
            Console.WriteLine($"Расширение: {result.Extension}");
            Console.WriteLine($"SHA256: {result.SHA256}");
            Console.WriteLine($"Score: {result.SuspiciousScore}");

            if (result.YaraMatches.Count > 0)
            {
                Console.WriteLine("YARA:");
                foreach (var m in result.YaraMatches)
                    Console.WriteLine("  - " + m);
            }

            foreach (var r in result.Reasons)
                Console.WriteLine("  - " + r);
        }

        public void Dispose()
        {
            _watcher.Dispose();
            _semaphore.Dispose();
        }
    }
}
