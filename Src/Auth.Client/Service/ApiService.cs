using System.Net;
using System.Net.Http.Json;
using Auth.Domain.ViewModel;

namespace Auth.Client.Service
{
    public class ApiService(HttpClient httpClient) : IApiService
    {
        public async Task<ApiResult<TResponse>> GetAsync<TResponse>(string url, CancellationToken ct = default)
        {
            try
            {
                var response = await httpClient.GetAsync(url, ct);
                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content
                        .ReadFromJsonAsync<ResponsePayload<TResponse>>(ct);
                    return new ApiResult<TResponse>
                    {
                        Success = result.Success,
                        Data = result.Data
                    };
                }

                return await LerErroHttpAsync<TResponse>(response, ct);
            }
            catch (Exception ex)
            {
                return MontaErroException<TResponse>(ex.Message);
            }
        }

        public async Task<ApiResult<TResponse>> PostAsync<TRequest, TResponse>(string url, TRequest data, CancellationToken ct = default)
        {
            try
            {
                var response = await httpClient.PostAsJsonAsync(url, data, ct);

                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content
                        .ReadFromJsonAsync<ResponsePayload<TResponse>>(ct);

                    return new ApiResult<TResponse>
                    {
                        Success = result.Success,
                        Data = result.Data
                    };
                }

                return await LerErroHttpAsync<TResponse>(response, ct);
            }
            catch (Exception ex)
            {
                return MontaErroException<TResponse>(ex.Message);
            }
        }

        public async Task<ApiResult<bool>> DeleteAsync(string url, CancellationToken ct = default)
        {
            try
            {
                var response = await httpClient.DeleteAsync(url, ct);
                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<ResponsePayload<bool>>(ct);

                    if (result.Success)
                        return new ApiResult<bool>
                        {
                            Success = result.Success,
                            Data = result.Data
                        };
                }

                return await LerErroHttpAsync<bool>(response, ct);
            }
            catch (Exception ex)
            {
                return MontaErroException<bool>(ex.Message);
            }
        }

        public async Task<ApiResult<TResponse>> PutAsync<TRequest, TResponse>(string url, TRequest data, CancellationToken ct = default)
        {
            try
            {
                var response = await httpClient.PutAsJsonAsync(url, data, ct);

                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content
                        .ReadFromJsonAsync<ResponsePayload<TResponse>>(ct);

                    return new ApiResult<TResponse>
                    {
                        Success = result.Success,
                        Data = result.Data
                    };
                }

                return await LerErroHttpAsync<TResponse>(response, ct);
            }
            catch (Exception ex)
            {
                return MontaErroException<TResponse>(ex.Message);
            }
        }

        private static async Task<ApiResult<TResponse>> LerErroHttpAsync<TResponse>(HttpResponseMessage response, CancellationToken ct)
        {
            try
            {
                if (response.Content.Headers.ContentLength is null or > 0)
                {
                    var error = await response.Content.ReadFromJsonAsync<ResponseError<string[]>>(cancellationToken: ct);
                    if (error?.Errors is { Length: > 0 })
                    {
                        return new ApiResult<TResponse>
                        {
                            Success = false,
                            Errors = error.Errors
                        };
                    }
                }
            }
            catch
            {
                // Ignora erro de parse caso a resposta HTTP (ex.: 401/403/500) não contenha JSON válido.
            }

            var defaultMessage = response.StatusCode switch
            {
                HttpStatusCode.Unauthorized => "Sessão expirada ou usuário não autenticado.",
                HttpStatusCode.Forbidden => "Usuário não tem permissão para acessar este recurso.",
                _ => $"Erro inesperado ({(int)response.StatusCode})."
            };

            return new ApiResult<TResponse>
            {
                Success = false,
                Errors = [defaultMessage]
            };
        }

        private ApiResult<TResponse> MontaErroException<TResponse>(string ex)
            => new ApiResult<TResponse>
            {
                Success = false,
                Errors = [ex]
            };
    }
}
