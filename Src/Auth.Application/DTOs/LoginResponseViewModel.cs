using Auth.Domain.Entities;

namespace Auth.Application.DTOs;

public class LoginResponseViewModel
{
        public string AccessToken { get; set; }
        public double ExpiresIn { get; set; }
        public UserTokenViewModel UserToken { get; set; }
}
