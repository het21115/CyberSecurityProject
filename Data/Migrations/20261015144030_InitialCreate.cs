using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberSecurityFileRiskAnalysis.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    UserId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Username = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    Email = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    PasswordHash = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    TotpSecretEncrypted = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    MfaEnabled = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.UserId);
                });

            migrationBuilder.CreateTable(
                name: "UploadedDocuments",
                columns: table => new
                {
                    DocumentId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserId = table.Column<int>(type: "int", nullable: false),
                    OriginalFileName = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    StoredFileName = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    StoredFilePath = table.Column<string>(type: "nvarchar(1024)", maxLength: 1024, nullable: false),
                    FileHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    FileSize = table.Column<long>(type: "bigint", nullable: false),
                    ContentType = table.Column<string>(type: "nvarchar(127)", maxLength: 127, nullable: false),
                    UploadedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UploadedDocuments", x => x.DocumentId);
                    table.ForeignKey(
                        name: "FK_UploadedDocuments_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "UserId",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "FileRiskAnalysisResults",
                columns: table => new
                {
                    AnalysisId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    DocumentId = table.Column<int>(type: "int", nullable: false),
                    ScannerName = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    ScanStatus = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    RiskScore = table.Column<int>(type: "int", nullable: false),
                    RiskClassification = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    DetectionDetails = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: false),
                    AnalysisSummary = table.Column<string>(type: "nvarchar(4000)", maxLength: 4000, nullable: false),
                    AnalysedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FileRiskAnalysisResults", x => x.AnalysisId);
                    table.ForeignKey(
                        name: "FK_FileRiskAnalysisResults_UploadedDocuments_DocumentId",
                        column: x => x.DocumentId,
                        principalTable: "UploadedDocuments",
                        principalColumn: "DocumentId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_FileRiskAnalysisResults_DocumentId_AnalysedAt",
                table: "FileRiskAnalysisResults",
                columns: new[] { "DocumentId", "AnalysedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_UploadedDocuments_UserId_UploadedAt",
                table: "UploadedDocuments",
                columns: new[] { "UserId", "UploadedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_Username",
                table: "Users",
                column: "Username",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FileRiskAnalysisResults");

            migrationBuilder.DropTable(
                name: "UploadedDocuments");

            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}
