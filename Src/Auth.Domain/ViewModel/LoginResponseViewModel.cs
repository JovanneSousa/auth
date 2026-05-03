using Auth.Domain.Entities;

namespace Auth.Domain.ViewModel;
public class LoginResponseViewModel
{
        public required string AccessToken { get; set; }
        public required double ExpiresIn { get; set; }
        public required UserTokenViewModel UserToken { get; set; }
}
