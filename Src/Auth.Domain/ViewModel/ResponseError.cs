namespace Auth.Domain.ViewModel
{

    public class ResponseError<T>
    {
        public bool Success { get; set; }
        public required T Errors { get; set; }
    }
}
