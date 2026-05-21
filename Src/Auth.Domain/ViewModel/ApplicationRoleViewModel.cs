
namespace Auth.Domain.ViewModel
{
    public class ApplicationRoleViewModel
    {
        public required string Id { get; set; }
        public required string Name { get; set; }
        public required string SystemId { get; set; }
        public required List<ApplicationClaimViewModel> Claims { get; set; }
    }
}
