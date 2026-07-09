namespace Auth.Domain.Models
{
    public class RefreshTokenRequestViewModel
    {
        public required string RefreshToken { get; set; }
        public required string System { get; set; }
    }
}
