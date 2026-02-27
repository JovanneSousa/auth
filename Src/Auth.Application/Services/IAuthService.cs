using Auth.Application.DTOs;

namespace Auth.Application.Services;

public interface IAuthService
{
    Task<bool> AdicionarUsuarioAsync(RegisterUserViewModel registerUser);
    Task<LoginResponseViewModel?> LogarUsuarioAsync(LoginUserViewModel loginUser);
    Task<bool> GerarTokenResetarSenha(ForgotPassViewModel data);
    Task<bool> RecuperarSenha(ResetPassViewModel data);
    Task<IEnumerable<AuthUserViewModel>> ListarAuthUser();
}
