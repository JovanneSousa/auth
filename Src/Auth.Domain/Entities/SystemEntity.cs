namespace Auth.Domain.Entities
{
    public class SystemEntity
    {
        public required string Id { get; set; }
        public required string Name { get; set; }
        public required string Url { get; set; }

        public IEnumerable<string> Validate()
        {
            if (string.IsNullOrWhiteSpace(Id))
                yield return "O campo Id é obrigatório.";

            if (string.IsNullOrWhiteSpace(Name))
                yield return "O campo Name é obrigatório.";

            if (string.IsNullOrWhiteSpace(Url))
                yield return "O campo Url é obrigatório.";
        }

        public bool IsValid() => !Validate().Any();
    }
}
