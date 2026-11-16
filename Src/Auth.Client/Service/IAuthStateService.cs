namespace Auth.Client.Service
{
    public interface IAuthStateService
    {
        bool IsInitialized { get; }
        bool IsAuthenticated { get; }
        string UserEmail { get; }
        event Action OnChange;

        Task InitializeAsync();
        Task<string> GetValidAccessTokenAsync(CancellationToken ct = default);
        Task<ApiResult<bool>> LoginAsync(string email, string password, CancellationToken ct = default);
        Task<bool> TryRefreshTokenAsync(CancellationToken ct = default);
        Task LogoutAsync();
    }
}
