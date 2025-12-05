namespace auth.Models;

public class UserTokenViewModel
{
        public string Id { get; set; }
        public string Name { get; set; }
        public IEnumerable<ClaimViewModel> Claims { get; set; }
}
