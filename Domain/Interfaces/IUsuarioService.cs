using auth.DTOs;

namespace auth.Domain.Interfaces;

public interface IUsuarioService
{
    Task<LoginResponseViewModel?> AdicionarUsuarioAsync(RegisterUserViewModel registerUser);
    Task<LoginResponseViewModel?> LogarUsuarioAsync(LoginUserViewModel loginUser);
    Task<string> RecuperarSenha(ForgotPassViewModel data);
}
