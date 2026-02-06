using auth.DTOs;

namespace auth.Domain.Interfaces;

public interface IUsuarioService
{
    Task<LoginResponseViewModel?> AdicionarUsuarioAsync(RegisterUserViewModel registerUser);
    Task<LoginResponseViewModel?> LogarUsuarioAsync(LoginUserViewModel loginUser);
    Task<string> GerarTokenResetSenha(string email);
    Task<bool> ResetarSenha(string email, string token, string password);
}
