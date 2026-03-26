namespace Auth.Domain.ViewModel
{
    public class ApplicationRoleViewModel
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public List<string> Claims { get; set; }
    }
}
