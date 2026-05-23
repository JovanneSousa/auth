namespace Auth.Client.Service
{
    public class ApiResult<T>
    {
        public bool Success { get; set; }
        public T? Data { get; set; }
        public string[] Errors { get; set; } = [];
    }
}
