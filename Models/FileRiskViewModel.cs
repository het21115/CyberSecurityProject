using System.ComponentModel.DataAnnotations;

namespace CyberSecurityFileRiskAnalysis.Models;

public sealed class FileRiskViewModel
{
    [Required]
    public IFormFile? File { get; set; }

    public FileRiskReportViewModel? Report { get; set; }

    public IReadOnlyList<FileRiskHistoryViewModel> History { get; set; } = [];
}

public sealed record FileRiskReportViewModel(
    string FileName,
    long FileSize,
    string Hash,
    string ContentType,
    string Classification,
    int RiskScore,
    string Summary,
    string Details,
    string ScanStatus,
    DateTime AnalysedAt);

public sealed record FileRiskHistoryViewModel(
    string FileName,
    string Hash,
    string ContentType,
    long FileSize,
    string Classification,
    int RiskScore,
    string Summary,
    string ScanStatus,
    DateTime AnalysedAt);
