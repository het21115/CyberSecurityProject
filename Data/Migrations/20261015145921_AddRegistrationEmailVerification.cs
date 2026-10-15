using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberSecurityFileRiskAnalysis.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddRegistrationEmailVerification : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RegistrationEmailVerifications",
                columns: table => new
                {
                    RegistrationEmailVerificationId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Username = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    Email = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    PasswordHash = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    OtpHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    OtpSalt = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    FailedAttempts = table.Column<int>(type: "int", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RegistrationEmailVerifications", x => x.RegistrationEmailVerificationId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_RegistrationEmailVerifications_Email",
                table: "RegistrationEmailVerifications",
                column: "Email");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RegistrationEmailVerifications");
        }
    }
}
