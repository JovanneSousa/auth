namespace Auth.Domain.DTOs
{
    public class SystemViewModel
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Url { get; set; }
        public List<ApplicationRoleViewModel> Permissoes { get; set; }

    }
}
