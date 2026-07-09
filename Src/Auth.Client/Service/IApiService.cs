namespace Auth.Client.Service
{
    public interface IApiService
    {
        Task<ApiResult<TResponse>> PostAsync<TRequest, TResponse>(
            string url,
            TRequest data,
            CancellationToken ct = default);

        Task<ApiResult<TResponse>> GetAsync<TResponse>(
            string url,
            CancellationToken ct = default);

        Task<ApiResult<bool>> DeleteAsync(string url, CancellationToken ct = default);
        Task<ApiResult<TResponse>> PutAsync<TRequest, TResponse>(string url, TRequest data, CancellationToken ct = default);
    }
}
