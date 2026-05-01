namespace Auth.Domain.ViewModel
{
    public class SystemViewModel
    {
        public required string Id { get; set; }
        public required string Name { get; set; }
        public required string Url { get; set; }
        public required List<ApplicationRoleViewModel> Permissoes { get; set; }

    }
}
