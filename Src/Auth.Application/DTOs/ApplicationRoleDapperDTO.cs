namespace Auth.Application.DTOs
{
    public class ApplicationRoleDapperDTO
    {
        public string RoleId { get; init; }
        public string Name { get; init; }
        public List<string> Claims { get; init; }

        public ApplicationRoleDapperDTO(
            string roleId, 
            string name, 
            List<string> claims
            )
        {
            RoleId = roleId;
            Name = name;
            Claims = claims;
        }
    }
}
