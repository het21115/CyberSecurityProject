using CyberSecurityFileRiskAnalysis.Models;
using Microsoft.EntityFrameworkCore;

namespace CyberSecurityFileRiskAnalysis.Data;

public sealed class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : DbContext(options)
{
    public DbSet<User> Users => Set<User>();

    public DbSet<UploadedDocument> UploadedDocuments => Set<UploadedDocument>();

    public DbSet<FileRiskAnalysisResult> FileRiskAnalysisResults => Set<FileRiskAnalysisResult>();

    public DbSet<RegistrationEmailVerification> RegistrationEmailVerifications => Set<RegistrationEmailVerification>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.ToTable("Users");
            entity.HasKey(user => user.UserId);
            entity.Property(user => user.Username).HasMaxLength(50).IsRequired();
            entity.Property(user => user.Email).HasMaxLength(320).IsRequired();
            entity.Property(user => user.PasswordHash).HasMaxLength(512).IsRequired();
            entity.Property(user => user.TotpSecretEncrypted).HasMaxLength(2048);
            entity.Property(user => user.CreatedAt).HasColumnType("datetime2");
            entity.Property(user => user.FailedLoginAttempts).HasDefaultValue(0);
            entity.Property(user => user.IsLoginLocked).HasDefaultValue(false);
            entity.Property(user => user.LoginLockedUntilUtc).HasColumnType("datetime2");
            entity.HasIndex(user => user.Username).IsUnique();
            entity.HasIndex(user => user.Email).IsUnique();
        });

        modelBuilder.Entity<UploadedDocument>(entity =>
        {
            entity.ToTable("UploadedDocuments");
            entity.HasKey(document => document.DocumentId);
            entity.Property(document => document.OriginalFileName).HasMaxLength(255).IsRequired();
            entity.Property(document => document.StoredFileName).HasMaxLength(255).IsRequired();
            entity.Property(document => document.StoredFilePath).HasMaxLength(1024).IsRequired();
            entity.Property(document => document.FileHash).HasMaxLength(64).IsRequired();
            entity.Property(document => document.ContentType).HasMaxLength(127).IsRequired();
            entity.Property(document => document.UploadedAt).HasColumnType("datetime2");
            entity.HasIndex(document => new { document.UserId, document.UploadedAt });
            entity.HasOne(document => document.User)
                .WithMany(user => user.UploadedDocuments)
                .HasForeignKey(document => document.UserId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<FileRiskAnalysisResult>(entity =>
        {
            entity.ToTable("FileRiskAnalysisResults");
            entity.HasKey(result => result.AnalysisId);
            entity.Property(result => result.ScannerName).HasMaxLength(100).IsRequired();
            entity.Property(result => result.ScanStatus).HasMaxLength(32).IsRequired();
            entity.Property(result => result.RiskClassification).HasMaxLength(32).IsRequired();
            entity.Property(result => result.DetectionDetails).HasMaxLength(4000).IsRequired();
            entity.Property(result => result.AnalysisSummary).HasMaxLength(4000).IsRequired();
            entity.Property(result => result.AnalysedAt).HasColumnType("datetime2");
            entity.HasIndex(result => new { result.DocumentId, result.AnalysedAt });
            entity.HasOne(result => result.Document)
                .WithMany(document => document.AnalysisResults)
                .HasForeignKey(result => result.DocumentId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<RegistrationEmailVerification>(entity =>
        {
            entity.ToTable("RegistrationEmailVerifications");
            entity.HasKey(verification => verification.RegistrationEmailVerificationId);
            entity.Property(verification => verification.Username).HasMaxLength(50).IsRequired();
            entity.Property(verification => verification.Email).HasMaxLength(320).IsRequired();
            entity.Property(verification => verification.PasswordHash).HasMaxLength(512).IsRequired();
            entity.Property(verification => verification.OtpHash).HasMaxLength(64).IsRequired();
            entity.Property(verification => verification.OtpSalt).HasMaxLength(64).IsRequired();
            entity.Property(verification => verification.ExpiresAt).HasColumnType("datetime2");
            entity.Property(verification => verification.CreatedAt).HasColumnType("datetime2");
            entity.HasIndex(verification => verification.Email);
        });
    }
}
