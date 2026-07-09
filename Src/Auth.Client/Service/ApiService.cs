using Auth.Domain.ViewModel;
using System.Net.Http.Json;
using static MudBlazor.CategoryTypes;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Auth.Client.Service
{
    public class ApiService(HttpClient httpClient) : IApiService
    {
        public async Task<ApiResult<TResponse>> GetAsync<TResponse>(string url, CancellationToken ct = default)
        {
            try
            {
                var respose = await httpClient.GetAsync(url, ct);
                if (respose.IsSuccessStatusCode)
                {
                    var result = await respose.Content
                        .ReadFromJsonAsync<ResponsePayload<TResponse>>(ct);
                    return new ApiResult<TResponse>
                    {
                        Success = result.Success,
                        Data = result.Data
                    };
                }
                var error = await respose.Content.ReadFromJsonAsync<ResponseError<string[]>>();
                return MontaErro<TResponse>(error);

            } catch (Exception ex)
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

                var error = await response.Content
                    .ReadFromJsonAsync<ResponseError<string[]>>(ct);

                return MontaErro<TResponse>(error);
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
                var response = await httpClient.DeleteAsync(url);
                if(response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<ResponsePayload<bool>>();

                    if (result.Success)
                        return new ApiResult<bool>
                        {
                            Success = result.Success,
                            Data = result.Data
                        };
                }
                var erro = await response.Content.ReadFromJsonAsync<ResponseError<string[]>>();
                return MontaErro<bool>(erro);
            } catch (Exception ex)
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
                var error = await response.Content.ReadFromJsonAsync<ResponseError<string[]>>();
                return MontaErro<TResponse>(error);
            }
            catch (Exception ex)
            {
                return MontaErroException<TResponse>(ex.Message);   
            }
        }

        private ApiResult<TResponse> MontaErroException<TResponse>(string ex)
            => new ApiResult<TResponse>
            {
                Success = false,
                Errors = [ex]
            };

        private ApiResult<TResponse> MontaErro<TResponse>(ResponseError<string[]> errors)
            => new ApiResult<TResponse>
            {
                Success = errors.Success,
                Errors = errors?.Errors.Length > 0 ? errors.Errors : ["Erro inesperado"]
            };
    }
}
