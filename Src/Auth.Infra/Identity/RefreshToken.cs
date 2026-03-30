namespace Auth.Infra.Identity
{
    public class RefreshToken
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid Token { get; set; } = Guid.NewGuid();
        public string UserName { get; set; }
        public DateTime ExpirationDate { get; set; }
    }
}
