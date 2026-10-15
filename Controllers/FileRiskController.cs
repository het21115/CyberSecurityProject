using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using CyberSecurityFileRiskAnalysis.Data;
using CyberSecurityFileRiskAnalysis.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CyberSecurityFileRiskAnalysis.Controllers;

[Authorize]
public class FileRiskController(
    ApplicationDbContext dbContext,
    IWebHostEnvironment environment,
    IConfiguration configuration) : Controller
{
    private const long MaxUploadBytes = 1024L * 1024 * 1024;

    private static readonly HashSet<string> AllowedExtensions =
        [".txt", ".csv", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".png", ".jpg", ".jpeg", ".zip"];

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var userId = int.Parse(User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)!.Value);
        var reportData = await dbContext.UploadedDocuments
            .Where(document => document.UserId == userId)
            .OrderByDescending(document => document.UploadedAt)
            .SelectMany(document => document.AnalysisResults
                .OrderByDescending(result => result.AnalysedAt)
                .Take(1)
                .Select(result => new
                {
                    document.OriginalFileName,
                    document.FileSize,
                    document.FileHash,
                    document.ContentType,
                    result.RiskClassification,
                    result.RiskScore,
                    result.AnalysisSummary,
                    result.DetectionDetails,
                    result.ScanStatus,
                    result.AnalysedAt
                }))
            .FirstOrDefaultAsync();
        var report = reportData is null
            ? null
            : new FileRiskReportViewModel(
                reportData.OriginalFileName,
                reportData.FileSize,
                reportData.FileHash,
                reportData.ContentType,
                reportData.RiskClassification,
                reportData.RiskScore,
                GetDisplaySummary(reportData.AnalysisSummary, reportData.DetectionDetails, reportData.RiskClassification, reportData.ContentType),
                reportData.DetectionDetails,
                reportData.ScanStatus,
                reportData.AnalysedAt);

        var history = await LoadHistoryAsync(userId);
        var model = new FileRiskViewModel { Report = report, History = history };
        return View("FileRisk", model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [RequestSizeLimit(MaxUploadBytes)]
    public async Task<IActionResult> Analyze(FileRiskViewModel model)
    {
        if (model.File is null || model.File.Length == 0)
            ModelState.AddModelError(nameof(model.File), "Choose a non-empty file.");

        var maxSize = configuration.GetValue<long?>("FileAnalysis:MaxFileSizeBytes") ?? MaxUploadBytes;
        if (model.File?.Length > maxSize)
            ModelState.AddModelError(nameof(model.File), $"Files must be {maxSize / (1024 * 1024)} MB or smaller.");

        var extension = model.File is null ? string.Empty : Path.GetExtension(model.File.FileName).ToLowerInvariant();
        if (model.File is not null && !AllowedExtensions.Contains(extension))
            ModelState.AddModelError(nameof(model.File), "This file type is not supported.");

        if (!ModelState.IsValid)
        {
            var historyUserId = int.Parse(User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)!.Value);
            model.History = await LoadHistoryAsync(historyUserId);
            return View("FileRisk", model);
        }

        var userId = int.Parse(User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)!.Value);
        var uploadDirectory = Path.Combine(environment.ContentRootPath, "App_Data", "Uploads");
        Directory.CreateDirectory(uploadDirectory);
        var storedName = $"{Guid.NewGuid():N}{extension}";
        var storedPath = Path.Combine(uploadDirectory, storedName);

        await using (var input = model.File!.OpenReadStream())
        await using (var output = System.IO.File.Create(storedPath))
        {
            await input.CopyToAsync(output);
        }

        await using var hashStream = System.IO.File.OpenRead(storedPath);
        var hash = Convert.ToHexString(await SHA256.HashDataAsync(hashStream));
        var risk = await EvaluateRiskAsync(storedPath, extension, model.File.FileName);
        var document = new UploadedDocument
        {
            UserId = userId,
            OriginalFileName = Path.GetFileName(model.File.FileName),
            StoredFileName = storedName,
            StoredFilePath = storedPath,
            FileHash = hash,
            FileSize = model.File.Length,
            ContentType = model.File.ContentType ?? "application/octet-stream",
            UploadedAt = DateTime.UtcNow
        };
        document.AnalysisResults.Add(new FileRiskAnalysisResult
        {
            ScannerName = "Local heuristic scanner",
            ScanStatus = "Completed",
            RiskScore = risk.Score,
            RiskClassification = risk.Classification,
            DetectionDetails = risk.Details,
            AnalysisSummary = risk.Summary,
            AnalysedAt = DateTime.UtcNow
        });
        dbContext.UploadedDocuments.Add(document);
        await dbContext.SaveChangesAsync();

        TempData["AnalysisClassification"] = risk.Classification;
        TempData["AnalysisScore"] = risk.Score;
        TempData["AnalysisSummary"] = risk.Summary;
        TempData["Success"] = $"Analysis complete for {document.OriginalFileName}.";
        return RedirectToAction(nameof(Index));
    }

    private async Task<IReadOnlyList<FileRiskHistoryViewModel>> LoadHistoryAsync(int userId)
    {
        var historyData = await dbContext.UploadedDocuments
            .Where(document => document.UserId == userId)
            .OrderByDescending(document => document.UploadedAt)
            .SelectMany(document => document.AnalysisResults
                .OrderByDescending(result => result.AnalysedAt)
                .Take(1)
                .Select(result => new
                {
                    document.OriginalFileName,
                    document.FileHash,
                    document.ContentType,
                    document.FileSize,
                    result.RiskClassification,
                    result.RiskScore,
                    result.AnalysisSummary,
                    result.DetectionDetails,
                    result.ScanStatus,
                    result.AnalysedAt
                }))
            .Take(25)
            .ToListAsync();

        return historyData
            .Select(item => new FileRiskHistoryViewModel(
                item.OriginalFileName,
                item.FileHash,
                item.ContentType,
                item.FileSize,
                item.RiskClassification,
                item.RiskScore,
                GetDisplaySummary(item.AnalysisSummary, item.DetectionDetails, item.RiskClassification, item.ContentType),
                item.ScanStatus,
                item.AnalysedAt))
            .ToList();
    }

    private static string GetDisplaySummary(
        string storedSummary,
        string details,
        string classification,
        string contentType)
    {
        if (!storedSummary.StartsWith("Only low-risk indicators", StringComparison.OrdinalIgnoreCase) &&
            !storedSummary.StartsWith("Some risk indicators", StringComparison.OrdinalIgnoreCase))
            return storedSummary;

        var findings = details
            .Split(". ", StringSplitOptions.RemoveEmptyEntries)
            .Where(detail => !detail.StartsWith("File type baseline", StringComparison.OrdinalIgnoreCase))
            .Take(2)
            .ToArray();

        if (findings.Length == 0)
            return $"{GetDocumentType(contentType)} passed the available security checks with no suspicious indicators detected.";

        var findingText = string.Join("; ", findings).TrimEnd('.');
        return classification switch
        {
            "High" => $"High-risk findings: {findingText}.",
            "Medium" => $"Review recommended: {findingText}.",
            _ => $"Low-risk finding: {findingText}."
        };
    }

    private static string GetDocumentType(string contentType) =>
        contentType switch
        {
            "application/pdf" => "PDF document",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "Word document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => "Excel document",
            _ => "The document"
        };

    private static async Task<(int Score, string Classification, string Details, string Summary)> EvaluateRiskAsync(
        string path, string extension, string originalFileName)
    {
        var factors = new List<string>();
        var score = extension switch
        {
            ".exe" or ".dll" or ".scr" or ".com" => 60,
            ".js" or ".vbs" or ".ps1" or ".bat" or ".cmd" => 45,
            ".zip" or ".rar" or ".7z" => 18,
            ".doc" or ".docx" or ".xls" or ".xlsx" or ".ppt" or ".pptx" => 12,
            ".pdf" => 10,
            ".jpg" or ".jpeg" or ".png" or ".gif" => 3,
            ".txt" or ".csv" => 2,
            _ => 18
        };
        factors.Add($"File type baseline: {score}%");

        await using var stream = System.IO.File.OpenRead(path);
        var buffer = new byte[(int)Math.Min(stream.Length, 1024 * 1024)];
        var read = await stream.ReadAsync(buffer);
        var text = System.Text.Encoding.UTF8.GetString(buffer, 0, read);
        var fileSize = stream.Length;
        if (fileSize > 500 * 1024 * 1024)
        {
            score += 8;
            factors.Add("Very large file: +8%");
        }
        else if (fileSize > 100 * 1024 * 1024)
        {
            score += 4;
            factors.Add("Large file: +4%");
        }

        var entropy = CalculateEntropy(buffer, read);
        var isCompressedOrContainer = extension is ".pdf" or ".zip" or ".rar" or ".7z"
            or ".docx" or ".xlsx" or ".pptx" or ".jpg" or ".jpeg" or ".png" or ".gif";
        if (!isCompressedOrContainer && read > 0 && entropy >= 7.5)
        {
            score += 15;
            factors.Add($"High byte entropy ({entropy:F2}/8): +15%");
        }
        else if (!isCompressedOrContainer && read > 0 && entropy >= 6.5)
        {
            score += 7;
            factors.Add($"Elevated byte entropy ({entropy:F2}/8): +7%");
        }

        if (HasUnexpectedSignature(extension, buffer, read))
        {
            score += 25;
            factors.Add("Content signature does not match the file extension: +25%");
        }

        if (extension is ".docx" or ".xlsx" or ".pptx")
            AnalyzeOfficeContainer(path, ref score, factors);
        else if (extension == ".pdf")
            AnalyzePdf(buffer, read, ref score, factors);

        var suspiciousIndicators = new[]
        {
            "powershell", "cmd.exe", "invoke-expression", "wscript.shell",
            "process.start", "rundll32", "regsvr32", "downloadstring",
            "http://", "https://", "autoopen", "document_open", "macro"
        };
        var isTextLike = extension is ".txt" or ".csv" or ".js" or ".vbs" or ".ps1" or ".bat" or ".cmd";
        var foundIndicators = isTextLike
            ? suspiciousIndicators
                .Where(indicator => text.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                .ToArray()
            : [];
        if (foundIndicators.Length > 0)
        {
            var indicatorPoints = Math.Min(45, foundIndicators.Length * 12);
            score += indicatorPoints;
            factors.Add($"Suspicious content ({string.Join(", ", foundIndicators)}): +{indicatorPoints}%");
        }

        if (Path.GetFileNameWithoutExtension(originalFileName).Contains('.', StringComparison.Ordinal))
        {
            score += 10;
            factors.Add("Multiple filename extensions: +10%");
        }

        score = Math.Clamp(score, 0, 100);
        var details = factors.Count == 0 ? "No analysis factors were detected." : string.Join(" ", factors);
        var classification = score >= 70 ? "High" : score >= 35 ? "Medium" : "Low";
        var summary = BuildSummary(classification, factors);
        return (score, classification, details, summary);
    }

    private static string BuildSummary(string classification, IReadOnlyList<string> factors)
    {
        var findings = factors
            .Where(factor => !factor.StartsWith("File type baseline", StringComparison.Ordinal))
            .Select(factor =>
            {
                var pointsIndex = factor.IndexOf(": +", StringComparison.Ordinal);
                return pointsIndex >= 0 ? factor[..pointsIndex] : factor;
            })
            .Take(2)
            .ToArray();

        if (findings.Length == 0)
            return "No suspicious indicators detected; the file passed basic type and structure checks.";

        var findingText = string.Join("; ", findings);
        return classification switch
        {
            "High" => $"High-risk findings: {findingText}. Do not open the file until it is verified.",
            "Medium" => $"Review recommended: {findingText}.",
            _ => $"Low-risk finding: {findingText}."
        };
    }

    private static void AnalyzeOfficeContainer(string path, ref int score, List<string> factors)
    {
        try
        {
            using var archive = ZipFile.OpenRead(path);
            var entries = archive.Entries.Select(entry => entry.FullName).ToArray();

            if (entries.Any(entry => entry.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)))
            {
                score += 35;
                factors.Add("Embedded VBA project detected: +35%");
            }

            if (entries.Any(entry => entry.Contains("externalLinks", StringComparison.OrdinalIgnoreCase)))
            {
                score += 15;
                factors.Add("External workbook link detected: +15%");
            }

            if (entries.Any(entry => entry.Contains("embeddings", StringComparison.OrdinalIgnoreCase)))
            {
                score += 10;
                factors.Add("Embedded object detected: +10%");
            }
        }
        catch (InvalidDataException)
        {
            score += 25;
            factors.Add("Office container is malformed: +25%");
        }
    }

    private static void AnalyzePdf(byte[] buffer, int length, ref int score, List<string> factors)
        {
            var pdfText = Encoding.Latin1.GetString(buffer, 0, length);

            AddPdfIndicator(pdfText, "/JavaScript", 30, "Embedded JavaScript detected", ref score, factors);
            AddPdfIndicator(pdfText, "/JS", 30, "Embedded JavaScript action detected", ref score, factors);
            AddPdfIndicator(pdfText, "/OpenAction", 18, "Automatic document action detected", ref score, factors);
            AddPdfIndicator(pdfText, "/AA", 18, "Additional automatic action detected", ref score, factors);
            AddPdfIndicator(pdfText, "/Launch", 35, "External application launch action detected", ref score, factors);
            AddPdfIndicator(pdfText, "/EmbeddedFile", 15, "Embedded file detected", ref score, factors);
            AddPdfIndicator(pdfText, "/Filespec", 15, "Embedded file specification detected", ref score, factors);
            AddPdfIndicator(pdfText, "/URI", 8, "External link action detected", ref score, factors);
            AddPdfIndicator(pdfText, "/AcroForm", 4, "Interactive form detected", ref score, factors);
            AddPdfIndicator(pdfText, "/Encrypt", 3, "Encrypted PDF detected", ref score, factors);

            var objectCount = CountOccurrences(pdfText, " obj");
            if (objectCount > 5000)
            {
                score += 12;
                factors.Add($"Unusually large PDF object count ({objectCount}): +12%");
            }

            if (!pdfText.Contains("%%EOF", StringComparison.Ordinal))
            {
                score += 12;
                factors.Add("PDF end marker is missing: +12%");
            }
        }

    private static void AddPdfIndicator(
            string content,
            string indicator,
            int points,
            string description,
            ref int score,
            List<string> factors)
        {
            if (!content.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                return;

            score += points;
            factors.Add($"{description}: +{points}%");
        }

    private static int CountOccurrences(string content, string value)
        {
            var count = 0;
            var index = 0;
            while ((index = content.IndexOf(value, index, StringComparison.Ordinal)) >= 0)
            {
                count++;
                index += value.Length;
            }
            return count;
        }
    private static double CalculateEntropy(byte[] buffer, int length)
    {
        if (length == 0)
            return 0;

        var counts = new int[256];
        for (var index = 0; index < length; index++)
            counts[buffer[index]]++;

        var entropy = 0d;
        for (var index = 0; index < counts.Length; index++)
        {
            if (counts[index] == 0)
                continue;

            var probability = (double)counts[index] / length;
            entropy -= probability * Math.Log2(probability);
        }
        return entropy;
    }

    private static bool HasUnexpectedSignature(string extension, byte[] buffer, int length)
    {
        if (length < 4)
            return false;

        var isPdf = length >= 5 && Encoding.ASCII.GetString(buffer, 0, 5) == "%PDF-";
        var isZip = buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04;
        var isPng = length >= 8 && buffer[..8].SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 });
        var isJpeg = buffer[0] == 0xFF && buffer[1] == 0xD8 && buffer[2] == 0xFF;

        return extension switch
        {
            ".pdf" => !isPdf,
            ".zip" or ".docx" or ".xlsx" or ".pptx" => !isZip,
            ".png" => !isPng,
            ".jpg" or ".jpeg" => !isJpeg,
            _ => false
        };
    }
}
