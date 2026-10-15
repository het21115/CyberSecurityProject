namespace CyberSecurityFileRiskAnalysis.Models;

public sealed class User
{
    public int UserId { get; set; }

    public string Username { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;

    public string? TotpSecretEncrypted { get; set; }

    public bool MfaEnabled { get; set; }

    public DateTime CreatedAt { get; set; }

    public bool IsActive { get; set; }

    public int FailedLoginAttempts { get; set; }

    public bool IsLoginLocked { get; set; }

    public DateTime? LoginLockedUntilUtc { get; set; }

    public ICollection<UploadedDocument> UploadedDocuments { get; } = [];
}
