namespace CyberSecurityFileRiskAnalysis.Models;

public sealed class RegistrationEmailVerification
{
    public int RegistrationEmailVerificationId { get; set; }

    public string Username { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;

    public string OtpHash { get; set; } = string.Empty;

    public string OtpSalt { get; set; } = string.Empty;

    public DateTime ExpiresAt { get; set; }

    public int FailedAttempts { get; set; }

    public DateTime CreatedAt { get; set; }
}
