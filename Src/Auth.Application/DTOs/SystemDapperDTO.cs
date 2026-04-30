namespace Auth.Application.DTOs
{
    public class SystemDapperDTO
    {
        public string SystemId { get; set; }
        public string Name { get; set; }
        public string Url { get; set; }
        public List<ApplicationRoleDapperDTO> Permissoes { get; set; }

        public SystemDapperDTO(List<ApplicationRoleDapperDTO> permissoes, string url, string name, string systemId)
        {
            Permissoes = permissoes;
            Url = url;
            Name = name;
            SystemId = systemId;
        }
    }
}
