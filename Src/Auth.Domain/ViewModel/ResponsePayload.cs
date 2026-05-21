namespace Auth.Domain.ViewModel
{
    public class ResponsePayload<T>
    {
        public required bool Success { get; set; }
        public required T Data { get; set; }
    }
}
