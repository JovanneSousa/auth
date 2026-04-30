using System.ComponentModel.DataAnnotations;

namespace Auth.Domain.ViewModel
{
    public class ResetPassViewModel
    {
        [Required(ErrorMessage = "O campo {0} é obrigatório")]
        public required string Token { get; set; }

        [Required(ErrorMessage = "O campo {0} é obrigatório")]
        [EmailAddress(ErrorMessage = "O campo {0} está em formato inválido")]
        public required string Email { get; set; }

        [Required(ErrorMessage = "O campo {0} é obrigatório")]
        [StringLength(100, ErrorMessage = "O campo {0} precisa ter entre {2} e {1} caracteres", MinimumLength = 6)]
        public required string Password { get; set; }

        [Compare("Password", ErrorMessage = "As senhas não conferem")]
        public required string ConfirmPassword { get; set; }
    }
}
