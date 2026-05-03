namespace Auth.Domain.Entities;

public class UserTokenViewModel
{
        public required string Id { get; set; }
        public required string Name { get; set; }
        public required IEnumerable<ClaimViewModel> Claims { get; set; }
}
