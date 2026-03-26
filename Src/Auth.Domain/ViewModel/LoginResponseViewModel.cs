using Auth.Domain.Entities;

namespace Auth.Domain.ViewModel;
public class LoginResponseViewModel
{
        public string AccessToken { get; set; }
        public double ExpiresIn { get; set; }
        public UserTokenViewModel UserToken { get; set; }
}
