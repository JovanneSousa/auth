namespace Auth.Application.DTOs
{
    public class SystemDapperDTO
    {
        public required string SystemId { get; set; }
        public required string Name { get; set; }
        public required string Url { get; set; }
        public required List<ApplicationRoleDapperDTO> Permissoes { get; set; }
    }
}
