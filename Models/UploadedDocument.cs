namespace CyberSecurityFileRiskAnalysis.Models;

public sealed class UploadedDocument
{
    public int DocumentId { get; set; }

    public int UserId { get; set; }

    public string OriginalFileName { get; set; } = string.Empty;

    public string StoredFileName { get; set; } = string.Empty;

    public string StoredFilePath { get; set; } = string.Empty;

    public string FileHash { get; set; } = string.Empty;

    public long FileSize { get; set; }

    public string ContentType { get; set; } = string.Empty;

    public DateTime UploadedAt { get; set; }

    public User User { get; set; } = null!;

    public ICollection<FileRiskAnalysisResult> AnalysisResults { get; } = [];
}
