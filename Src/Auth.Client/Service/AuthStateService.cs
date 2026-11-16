using System.Globalization;
using System.Net.Http.Json;
using Auth.Domain.Models;
using Auth.Domain.ViewModel;
using Microsoft.JSInterop;

namespace Auth.Client.Service
{
    public class AuthStateService : IAuthStateService
    {
        private const string AccessTokenKey = "auth_access_token";
        private const string RefreshTokenKey = "auth_refresh_token";
        private const string ExpiresAtKey = "auth_expires_at";
        private const string UserEmailKey = "auth_user_email";
        private const string AdminSystem = "AUTH";

        private readonly HttpClient _httpClient;
        private readonly IJSRuntime _jsRuntime;
        private readonly SemaphoreSlim _refreshLock = new(1, 1);

        private string _accessToken;
        private string _refreshToken;
        private DateTime _expiresAtUtc = DateTime.MinValue;

        public bool IsInitialized { get; private set; }
        public bool IsAuthenticated => !string.IsNullOrWhiteSpace(_accessToken) && _expiresAtUtc > DateTime.UtcNow;
        public string UserEmail { get; private set; } = string.Empty;

        public event Action OnChange;

        public AuthStateService(HttpClient httpClient, IJSRuntime jsRuntime)
        {
            _httpClient = httpClient;
            _jsRuntime = jsRuntime;
        }

        public async Task InitializeAsync()
        {
            if (IsInitialized)
                return;

            try
            {
                _accessToken = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", AccessTokenKey);
                _refreshToken = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", RefreshTokenKey);
                UserEmail = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", UserEmailKey) ?? string.Empty;

                var expiresAtRaw = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", ExpiresAtKey);
                if (!string.IsNullOrWhiteSpace(expiresAtRaw) &&
                    DateTime.TryParse(expiresAtRaw, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsedExpires))
                {
                    _expiresAtUtc = parsedExpires;
                }

                if (!string.IsNullOrWhiteSpace(_accessToken) && _expiresAtUtc <= DateTime.UtcNow.AddSeconds(30))
                {
                    await TryRefreshTokenAsync();
                }
            }
            catch
            {
                await ClearSessionAsync();
            }
            finally
            {
                IsInitialized = true;
                NotifyStateChanged();
            }
        }

        public async Task<string> GetValidAccessTokenAsync(CancellationToken ct = default)
        {
            if (!IsInitialized)
                await InitializeAsync();

            if (!string.IsNullOrWhiteSpace(_accessToken) && _expiresAtUtc <= DateTime.UtcNow.AddSeconds(30))
            {
                await TryRefreshTokenAsync(ct);
            }

            return _accessToken;
        }

        public async Task<ApiResult<bool>> LoginAsync(string email, string password, CancellationToken ct = default)
        {
            try
            {
                var payload = new LoginUserViewModel
                {
                    Email = email?.Trim() ?? string.Empty,
                    Password = password ?? string.Empty,
                    System = AdminSystem
                };

                var response = await _httpClient.PostAsJsonAsync("api/auth/login", payload, ct);

                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<ResponsePayload<LoginTokenEnvelope>>(cancellationToken: ct);
                    var loginData = result?.Data?.Token;

                    if (result is { Success: true } && loginData is not null && !string.IsNullOrWhiteSpace(loginData.AccessToken))
                    {
                        await SaveSessionAsync(loginData, payload.Email);
                        IsInitialized = true;
                        NotifyStateChanged();

                        return new ApiResult<bool>
                        {
                            Success = true,
                            Data = true
                        };
                    }
                }

                var error = await ReadErrorAsync(response, ct);
                return new ApiResult<bool>
                {
                    Success = false,
                    Errors = error
                };
            }
            catch (Exception ex)
            {
                return new ApiResult<bool>
                {
                    Success = false,
                    Errors = [ex.Message]
                };
            }
        }

        public async Task<bool> TryRefreshTokenAsync(CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(_refreshToken))
                return false;

            await _refreshLock.WaitAsync(ct);
            try
            {
                if (!string.IsNullOrWhiteSpace(_accessToken) && _expiresAtUtc > DateTime.UtcNow.AddSeconds(30))
                    return true;

                var request = new RefreshTokenRequestViewModel
                {
                    RefreshToken = _refreshToken,
                    System = AdminSystem
                };

                var response = await _httpClient.PostAsJsonAsync("api/auth/refresh-token", request, ct);
                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<ResponsePayload<LoginTokenEnvelope>>(cancellationToken: ct);
                    var tokenData = result?.Data?.Token;

                    if (result is { Success: true } && tokenData is not null && !string.IsNullOrWhiteSpace(tokenData.AccessToken))
                    {
                        await SaveSessionAsync(tokenData, UserEmail);
                        NotifyStateChanged();
                        return true;
                    }
                }

                await ClearSessionAsync();
                NotifyStateChanged();
                return false;
            }
            catch
            {
                await ClearSessionAsync();
                NotifyStateChanged();
                return false;
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        public async Task LogoutAsync()
        {
            await ClearSessionAsync();
            NotifyStateChanged();
        }

        private async Task SaveSessionAsync(LoginResponseViewModel loginData, string fallbackEmail)
        {
            _accessToken = loginData.AccessToken;
            _refreshToken = loginData.RefreshToken;
            var expiresInSeconds = loginData.ExpiresIn > 0 ? loginData.ExpiresIn : 3600;
            _expiresAtUtc = DateTime.UtcNow.AddSeconds(expiresInSeconds);
            UserEmail = !string.IsNullOrWhiteSpace(loginData.UserToken?.Name)
                ? loginData.UserToken.Name
                : fallbackEmail;

            await _jsRuntime.InvokeVoidAsync("localStorage.setItem", AccessTokenKey, _accessToken);
            await _jsRuntime.InvokeVoidAsync("localStorage.setItem", RefreshTokenKey, _refreshToken);
            await _jsRuntime.InvokeVoidAsync("localStorage.setItem", ExpiresAtKey, _expiresAtUtc.ToString("O", CultureInfo.InvariantCulture));
            await _jsRuntime.InvokeVoidAsync("localStorage.setItem", UserEmailKey, UserEmail);
        }

        private async Task ClearSessionAsync()
        {
            _accessToken = null;
            _refreshToken = null;
            _expiresAtUtc = DateTime.MinValue;
            UserEmail = string.Empty;

            try
            {
                await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", AccessTokenKey);
                await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", RefreshTokenKey);
                await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", ExpiresAtKey);
                await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", UserEmailKey);
            }
            catch
            {
                // Ignora falhas de JSInterop durante desconexão.
            }
        }

        private static async Task<string[]> ReadErrorAsync(HttpResponseMessage response, CancellationToken ct)
        {
            try
            {
                if (response.Content.Headers.ContentLength is null or > 0)
                {
                    var err = await response.Content.ReadFromJsonAsync<ResponseError<string[]>>(cancellationToken: ct);
                    if (err?.Errors is { Length: > 0 })
                        return err.Errors;
                }
            }
            catch
            {
                // Ignora erro de parse caso resposta não seja JSON no formato esperado.
            }

            return ["Falha ao autenticar. Verifique suas credenciais."];
        }

        private void NotifyStateChanged() => OnChange?.Invoke();

        private sealed class LoginTokenEnvelope
        {
            public LoginResponseViewModel Token { get; set; }
        }
    }
}
