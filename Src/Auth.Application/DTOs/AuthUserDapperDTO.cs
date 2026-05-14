namespace Auth.Application.DTOs
{
    public class AuthUserDapperDTO
    {
        public required string UserId { get; set;  }
        public required string Nome { get; set; }
        public required string Email { get; set; }
        public required List<SystemDapperDTO> Systems { get; set; }
    }
}
