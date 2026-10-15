namespace CyberSecurityFileRiskAnalysis.Models;

public sealed class FileRiskAnalysisResult
{
    public int AnalysisId { get; set; }

    public int DocumentId { get; set; }

    public string ScannerName { get; set; } = string.Empty;

    public string ScanStatus { get; set; } = string.Empty;

    public int RiskScore { get; set; }

    public string RiskClassification { get; set; } = string.Empty;

    public string DetectionDetails { get; set; } = string.Empty;

    public string AnalysisSummary { get; set; } = string.Empty;

    public DateTime AnalysedAt { get; set; }

    public UploadedDocument Document { get; set; } = null!;
}
