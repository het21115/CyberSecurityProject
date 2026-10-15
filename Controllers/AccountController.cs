using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Net.Mail;
using CyberSecurityFileRiskAnalysis.Data;
using CyberSecurityFileRiskAnalysis.Models;
using CyberSecurityFileRiskAnalysis.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CyberSecurityFileRiskAnalysis.Controllers;

public class AccountController(
    ApplicationDbContext dbContext,
    IPasswordHasher<User> passwordHasher,
    IEmailSender emailSender,
    ILogger<AccountController> logger) : Controller
{
    private const string CaptchaCharacters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    [HttpGet]
    public IActionResult Registration() => View(new RegistrationViewModel());

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Registration(RegistrationViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var username = model.Username.Trim();
        var email = model.Email.Trim().ToLowerInvariant();
        if (await dbContext.Users.AnyAsync(user => user.Username == username || user.Email == email))
        {
            ModelState.AddModelError(string.Empty, "That username or email address is already registered.");
            return View(model);
        }

        var pending = new RegistrationEmailVerification
        {
            Username = username,
            Email = email,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(10),
            OtpSalt = Convert.ToHexString(RandomNumberGenerator.GetBytes(16))
        };
        pending.PasswordHash = passwordHasher.HashPassword(new User(), model.Password);
        var otp = RandomNumberGenerator.GetInt32(100000, 1000000).ToString();
        pending.OtpHash = HashOtp(pending.OtpSalt, otp);

        var previous = await dbContext.RegistrationEmailVerifications
            .Where(verification => verification.Email == email)
            .ToListAsync();
        dbContext.RegistrationEmailVerifications.RemoveRange(previous);
        dbContext.RegistrationEmailVerifications.Add(pending);
        await dbContext.SaveChangesAsync();

        try
        {
            await emailSender.SendRegistrationOtpAsync(email, username, otp);
        }
        catch (Exception exception) when (exception is InvalidOperationException or SmtpException or FormatException)
        {
            dbContext.RegistrationEmailVerifications.Remove(pending);
            await dbContext.SaveChangesAsync();
            logger.LogError(exception, "Could not send registration OTP to {Email}", email);
            ModelState.AddModelError(string.Empty,
                $"We could not send the verification email: {exception.Message}");
            return View(model);
        }

        return RedirectToAction(nameof(VerifyEmail), new { id = pending.RegistrationEmailVerificationId });
    }

    [HttpGet]
    public async Task<IActionResult> VerifyEmail(int id)
    {
        var pending = await dbContext.RegistrationEmailVerifications.FindAsync(id);
        if (pending is null || pending.ExpiresAt <= DateTime.UtcNow)
            return RedirectToAction(nameof(Registration));

        ViewBag.Email = pending.Email;
        return View(new VerifyRegistrationEmailViewModel { VerificationId = id });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyEmail(VerifyRegistrationEmailViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var pending = await dbContext.RegistrationEmailVerifications.FindAsync(model.VerificationId);
        if (pending is null || pending.ExpiresAt <= DateTime.UtcNow)
        {
            ModelState.AddModelError(string.Empty, "This verification code has expired. Please register again.");
            return View(model);
        }

        if (pending.FailedAttempts >= 5 ||
            !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(pending.OtpHash),
                Convert.FromHexString(HashOtp(pending.OtpSalt, model.Otp))))
        {
            pending.FailedAttempts++;
            await dbContext.SaveChangesAsync();
            ModelState.AddModelError(string.Empty, "The verification code is incorrect or has been locked.");
            return View(model);
        }

        var user = new User
        {
            Username = pending.Username,
            Email = pending.Email,
            PasswordHash = pending.PasswordHash,
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };
        dbContext.Users.Add(user);
        dbContext.RegistrationEmailVerifications.Remove(pending);
        await dbContext.SaveChangesAsync();
        return RedirectToAction(nameof(Login));
    }

    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        var model = new LoginViewModel();
        SetCaptcha(model);
        return View(model);
    }

    [HttpGet]
    public IActionResult Captcha()
    {
        var model = new LoginViewModel();
        SetCaptcha(model);

        var random = new Random();
        var lines = string.Join(string.Empty, Enumerable.Range(0, 7).Select(_ =>
            $"<line x1=\"{random.Next(0, 180)}\" y1=\"{random.Next(8, 62)}\" x2=\"{random.Next(0, 180)}\" y2=\"{random.Next(8, 62)}\" />"));
        var circles = string.Join(string.Empty, Enumerable.Range(0, 18).Select(_ =>
            $"<circle cx=\"{random.Next(0, 180)}\" cy=\"{random.Next(5, 65)}\" r=\"{random.Next(1, 3)}\" />"));
        var characters = string.Join(string.Empty, model.CaptchaQuestion.Select((character, index) =>
            $"<text x=\"{18 + index * 25}\" y=\"{random.Next(42, 56)}\" transform=\"rotate({random.Next(-18, 19)} {18 + index * 25} 45)\">{character}</text>"));
        var svg = $$"""
            <svg xmlns="http://www.w3.org/2000/svg" width="180" height="70" viewBox="0 0 180 70" role="img" aria-label="CAPTCHA image">
              <rect width="180" height="70" rx="4" fill="#f7f4ff"/>
              <g stroke="#aaa0c8" stroke-width="1" opacity=".65">{{lines}}</g>
              <g fill="#8d82a8" opacity=".7">{{circles}}</g>
              <g fill="#183b64" font-family="Arial, sans-serif" font-size="29" font-weight="700" letter-spacing="2">{{characters}}</g>
            </svg>
            """;
        return Content(svg, "image/svg+xml");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
    {
        var expectedCaptcha = HttpContext.Session.GetString("LoginCaptchaAnswer");
        var captchaIsValid = !string.IsNullOrWhiteSpace(expectedCaptcha) &&
            string.Equals(model.CaptchaAnswer.Trim(), expectedCaptcha, StringComparison.OrdinalIgnoreCase);
        HttpContext.Session.Remove("LoginCaptchaAnswer");

        if (!captchaIsValid)
            ModelState.AddModelError(nameof(model.CaptchaAnswer), "The CAPTCHA answer is incorrect or has expired.");

        if (!ModelState.IsValid)
        {
            SetCaptcha(model);
            return View(model);
        }

        var identifier = model.UsernameOrEmail.Trim();
        var user = await dbContext.Users.SingleOrDefaultAsync(candidate =>
            candidate.Username == identifier || candidate.Email == identifier.ToLower());
        if (user is null || !user.IsActive)
        {
            ModelState.AddModelError(string.Empty, "Invalid username/email or password.");
            SetCaptcha(model);
            return View(model);
        }

        if (user.IsLoginLocked && user.LoginLockedUntilUtc > DateTime.UtcNow)
        {
            model.LockoutSecondsRemaining = Math.Max(
                1,
                (int)Math.Ceiling((user.LoginLockedUntilUtc.Value - DateTime.UtcNow).TotalSeconds));
            ModelState.AddModelError(string.Empty,
                "This account is temporarily locked after five failed login attempts.");
            SetCaptcha(model);
            return View(model);
        }

        if (user.IsLoginLocked)
        {
            user.FailedLoginAttempts = 0;
            user.IsLoginLocked = false;
            user.LoginLockedUntilUtc = null;
            await dbContext.SaveChangesAsync();
        }

        if (passwordHasher.VerifyHashedPassword(user, user.PasswordHash, model.Password) ==
            PasswordVerificationResult.Failed)
        {
            user.FailedLoginAttempts++;
            if (user.FailedLoginAttempts >= 5)
            {
                user.IsLoginLocked = true;
                user.LoginLockedUntilUtc = DateTime.UtcNow.AddMinutes(2);
                model.LockoutSecondsRemaining = 120;
                ModelState.AddModelError(string.Empty,
                    "This account is temporarily locked after five failed login attempts.");
            }
            else
            {
                var attemptsRemaining = 5 - user.FailedLoginAttempts;
                ModelState.AddModelError(string.Empty,
                    $"Invalid username/email or password. {attemptsRemaining} login attempt(s) remaining.");
            }

            await dbContext.SaveChangesAsync();
            SetCaptcha(model);
            return View(model);
        }

        user.FailedLoginAttempts = 0;
        user.IsLoginLocked = false;
        user.LoginLockedUntilUtc = null;
        await dbContext.SaveChangesAsync();
        await SignInAsync(user, model.RememberMe);
        return Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl!) : RedirectToAction("Index", "FileRisk");
    }

    private void SetCaptcha(LoginViewModel model)
    {
        var captcha = string.Create(6, 0, static (characters, _) =>
        {
            for (var index = 0; index < characters.Length; index++)
                characters[index] = CaptchaCharacters[RandomNumberGenerator.GetInt32(CaptchaCharacters.Length)];
        });

        model.CaptchaQuestion = captcha;
        HttpContext.Session.SetString("LoginCaptchaAnswer", captcha);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Login));
    }

    private static string HashOtp(string salt, string otp) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{salt}:{otp}")));

    private async Task SignInAsync(User user, bool isPersistent)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Email, user.Email)
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity), new AuthenticationProperties { IsPersistent = isPersistent });
    }
}
