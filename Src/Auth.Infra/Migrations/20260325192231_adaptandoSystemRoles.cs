using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.Infra.Migrations
{
    /// <inheritdoc />
    public partial class adaptandoSystemRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AspNetRoles_SystemId",
                table: "AspNetRoles");

            migrationBuilder.DropColumn(
                name: "Discriminator",
                table: "AspNetRoles");

            migrationBuilder.AlterColumn<string>(
                name: "SystemId",
                table: "AspNetRoles",
                type: "text",
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "text",
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_AspNetRoles_SystemId_Name",
                table: "AspNetRoles",
                columns: new[] { "SystemId", "Name" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_AspNetRoles_SystemEntity_SystemId",
                table: "AspNetRoles",
                column: "SystemId",
                principalTable: "SystemEntity",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AspNetRoles_SystemEntity_SystemId",
                table: "AspNetRoles");

            migrationBuilder.DropIndex(
                name: "IX_AspNetRoles_SystemId_Name",
                table: "AspNetRoles");

            migrationBuilder.AlterColumn<string>(
                name: "SystemId",
                table: "AspNetRoles",
                type: "text",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "text");

            migrationBuilder.AddColumn<string>(
                name: "Discriminator",
                table: "AspNetRoles",
                type: "character varying(21)",
                maxLength: 21,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetRoles_SystemId",
                table: "AspNetRoles",
                column: "SystemId");
        }
    }
}
