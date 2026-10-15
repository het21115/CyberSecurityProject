using System.ComponentModel.DataAnnotations;

namespace CyberSecurityFileRiskAnalysis.Models;

public sealed class RegistrationViewModel
{
    [Required, StringLength(50, MinimumLength = 3)]
    public string Username { get; set; } = string.Empty;

    [Required, EmailAddress, StringLength(320)]
    public string Email { get; set; } = string.Empty;

    [Required, DataType(DataType.Password), StringLength(100, MinimumLength = 8)]
    public string Password { get; set; } = string.Empty;

    [Required, DataType(DataType.Password), Compare(nameof(Password))]
    public string ConfirmPassword { get; set; } = string.Empty;
}

public sealed class LoginViewModel
{
    [Required]
    public string UsernameOrEmail { get; set; } = string.Empty;

    [Required, DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    public bool RememberMe { get; set; }

    public string CaptchaQuestion { get; set; } = string.Empty;

    [Required(ErrorMessage = "Enter the CAPTCHA answer.")]
    public string CaptchaAnswer { get; set; } = string.Empty;

    public int LockoutSecondsRemaining { get; set; }
}

public sealed class VerifyRegistrationEmailViewModel
{
    public int VerificationId { get; set; }

    [Required, StringLength(6, MinimumLength = 6)]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "Enter the six-digit code from your email.")]
    public string Otp { get; set; } = string.Empty;
}
