using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Components;

namespace Auth.Client.Service
{
    public class AuthHeaderHandler : DelegatingHandler
    {
        private readonly IAuthStateService _authStateService;
        private readonly NavigationManager _navigationManager;

        public AuthHeaderHandler(IAuthStateService authStateService, NavigationManager navigationManager)
        {
            _authStateService = authStateService;
            _navigationManager = navigationManager;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri?.IsAbsoluteUri == true
                ? request.RequestUri.AbsolutePath
                : request.RequestUri?.OriginalString ?? string.Empty;
            var isAuthEndpoint = path.EndsWith("api/auth/login", StringComparison.OrdinalIgnoreCase) ||
                                 path.EndsWith("api/auth/refresh-token", StringComparison.OrdinalIgnoreCase);

            if (!isAuthEndpoint)
            {
                var token = await _authStateService.GetValidAccessTokenAsync(cancellationToken);
                if (!string.IsNullOrWhiteSpace(token))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                }
            }

            var response = await base.SendAsync(request, cancellationToken);

            if (!isAuthEndpoint && response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var refreshed = await _authStateService.TryRefreshTokenAsync(cancellationToken);
                if (refreshed)
                {
                    var newToken = await _authStateService.GetValidAccessTokenAsync(cancellationToken);
                    using var retryRequest = await CloneHttpRequestMessageAsync(request);
                    retryRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newToken);

                    response.Dispose();
                    return await base.SendAsync(retryRequest, cancellationToken);
                }

                await _authStateService.LogoutAsync();
                _navigationManager.NavigateTo("/login", replace: true);
            }

            return response;
        }

        private static async Task<HttpRequestMessage> CloneHttpRequestMessageAsync(HttpRequestMessage request)
        {
            var clone = new HttpRequestMessage(request.Method, request.RequestUri)
            {
                Version = request.Version
            };

            if (request.Content != null)
            {
                var bytes = await request.Content.ReadAsByteArrayAsync();
                clone.Content = new ByteArrayContent(bytes);

                foreach (var header in request.Content.Headers)
                {
                    clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            foreach (var header in request.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            return clone;
        }
    }
}
