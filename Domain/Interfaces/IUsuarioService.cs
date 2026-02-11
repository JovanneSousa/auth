using auth.DTOs;

namespace auth.Domain.Interfaces;

public interface IUsuarioService
{
    Task<LoginResponseViewModel?> AdicionarUsuarioAsync(RegisterUserViewModel registerUser);
    Task<LoginResponseViewModel?> LogarUsuarioAsync(LoginUserViewModel loginUser);
    Task<bool> GerarTokenResetarSenha(ForgotPassViewModel data);
    Task<bool> RecuperarSenha(ResetPassViewModel data);
}
