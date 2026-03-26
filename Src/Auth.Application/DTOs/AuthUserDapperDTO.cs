namespace Auth.Application.DTOs
{
    public class AuthUserDapperDTO
    {
        public string UserId { get; set;  }
        public string Nome { get; set; }
        public string Email { get; set; }
        public List<SystemDapperDTO> Systems { get; set; }
    }
}
