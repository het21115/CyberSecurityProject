using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CyberSecurityFileRiskAnalysis.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddTemporaryLoginLockout : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "FailedLoginAttempts",
                table: "Users",
                type: "int",
                nullable: false,
                defaultValue: 0);
            migrationBuilder.AddColumn<bool>(
                name: "IsLoginLocked",
                table: "Users",
                type: "bit",
                nullable: false,
                defaultValue: false);
            migrationBuilder.AddColumn<DateTime>(
                name: "LoginLockedUntilUtc",
                table: "Users",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(name: "FailedLoginAttempts", table: "Users");
            migrationBuilder.DropColumn(name: "IsLoginLocked", table: "Users");
            migrationBuilder.DropColumn(name: "LoginLockedUntilUtc", table: "Users");
        }
    }
}
