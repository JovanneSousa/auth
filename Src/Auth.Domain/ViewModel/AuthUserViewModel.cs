namespace Auth.Domain.ViewModel
{
    public class AuthUserViewModel
    {
        public string Id { get; set;  }
        public string Nome { get; set; }
        public string Email { get; set; }
        public List<SystemViewModel> Systems { get; set; }
    }
}
