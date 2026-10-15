using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Options;

namespace CyberSecurityFileRiskAnalysis.Services;

public sealed class SmtpOptions
{
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 587;
    public bool EnableSsl { get; set; } = true;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string FromEmail { get; set; } = string.Empty;
    public string FromName { get; set; } = "CyberSecurity File Risk Analysis";
}

public interface IEmailSender
{
    Task SendRegistrationOtpAsync(string recipientEmail, string recipientName, string otp);
}

public sealed class SmtpEmailSender(IOptions<SmtpOptions> options, ILogger<SmtpEmailSender> logger)
    : IEmailSender
{
    public async Task SendRegistrationOtpAsync(string recipientEmail, string recipientName, string otp)
    {
        var settings = options.Value;
        if (string.IsNullOrWhiteSpace(settings.Host) ||
            string.IsNullOrWhiteSpace(settings.Username) ||
            string.IsNullOrWhiteSpace(settings.Password) ||
            string.IsNullOrWhiteSpace(settings.FromEmail))
        {
            throw new InvalidOperationException(
                "SMTP is incomplete. Set Smtp__Username, Smtp__Password, and Smtp__FromEmail. " +
                "For Gmail, use an App Password rather than the normal account password.");
        }

        using var message = new MailMessage
        {
            From = new MailAddress(settings.FromEmail, settings.FromName),
            Subject = "Your registration verification code",
            Body = $"Hello {recipientName},\n\nYour verification code is {otp}.\nIt expires in 10 minutes.\n\nIf you did not request this, ignore this email.",
            IsBodyHtml = false
        };
        message.To.Add(new MailAddress(recipientEmail));

        using var client = new SmtpClient(settings.Host, settings.Port)
        {
            EnableSsl = settings.EnableSsl,
            Credentials = new NetworkCredential(settings.Username, settings.Password),
            DeliveryMethod = SmtpDeliveryMethod.Network
        };
        await client.SendMailAsync(message);
        logger.LogInformation("Registration OTP sent to {RecipientEmail}", recipientEmail);
    }
}
