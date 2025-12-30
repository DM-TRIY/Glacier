namespace Glacier.Core.Quarantine;

public class UserModeFileIsolator : IFileIsolator
{
    public void Isolate(string sourcePath, string quarantinePath)
    {
        var dir = Path.GetDirectoryName(quarantinePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        File.Move(sourcePath, quarantinePath);
    }

    public void Restore(string quarantinePath, string originalPath)
    {
        var dir = Path.GetDirectoryName(originalPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        File.Move(quarantinePath, originalPath);
    }
}
