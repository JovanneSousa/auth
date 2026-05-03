namespace Auth.Domain.ViewModel
{
    public class AuthUserViewModel
    {
        public required string Id { get; set;  }
        public required string Nome { get; set; }
        public required string Email { get; set; }
        public required List<SystemViewModel> Systems { get; set; }
    }
}
