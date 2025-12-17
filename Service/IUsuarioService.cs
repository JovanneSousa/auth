using auth.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace auth.Service;

public interface IUsuarioService
{
    public Task<LoginResponseViewModel?> AdicionarUsuarioAsync(RegisterUserViewModel registerUser);
    public Task<LoginResponseViewModel?> LogarUsuarioAsync(LoginUserViewModel loginUser);
}
