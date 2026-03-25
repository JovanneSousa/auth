using Auth.Domain.Entities;

namespace Auth.Domain.DTOs
{
    public class UserDetailsViewModel
    {
        public string Nome { get; set; }
        public string Email { get; set; }
        public IEnumerable<SystemViewModel> Systems { get; set; }
    }
}
