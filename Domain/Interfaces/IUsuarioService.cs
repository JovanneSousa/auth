using auth.DTOs;

namespace auth.Domain.Interfaces;

public interface IUsuarioService
{
    public Task<LoginResponseViewModel?> AdicionarUsuarioAsync(RegisterUserViewModel registerUser);
    public Task<LoginResponseViewModel?> LogarUsuarioAsync(LoginUserViewModel loginUser);
}
