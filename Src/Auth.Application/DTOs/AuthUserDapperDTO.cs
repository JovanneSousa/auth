namespace Auth.Application.DTOs
{
    public class AuthUserDapperDTO
    {
        public string UserId { get; set;  }
        public string Nome { get; set; }
        public string Email { get; set; }
        public List<SystemDapperDTO> Systems { get; set; }

        public AuthUserDapperDTO(
            string userId, 
            string nome, 
            string email, 
            List<SystemDapperDTO> systems
            ) {
            UserId = userId;
            Nome = nome;
            Email = email;
            Systems = systems;
        }
    }
}
