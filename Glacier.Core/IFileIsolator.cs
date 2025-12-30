namespace Glacier.Core.Quarantine;

public interface IFileIsolator
{
    void Isolate(string sourcePath, string quarantinePath);
    void Restore(string quarantinePath, string originalPath);
}
