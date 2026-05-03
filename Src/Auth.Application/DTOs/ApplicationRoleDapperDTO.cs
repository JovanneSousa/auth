namespace Auth.Application.DTOs
{
    public class ApplicationRoleDapperDTO
    {
        public required string RoleId { get; init; }
        public required string Name { get; init; }
        public required List<string> Claims { get; init; }
    }
}
