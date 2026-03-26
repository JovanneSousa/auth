namespace Auth.Application.DTOs
{
    public class ApplicationRoleDapperDTO
    {
        public string RoleId { get; set; }
        public string Name { get; set; }
        public List<string> Claims { get; set; }
    }
}
