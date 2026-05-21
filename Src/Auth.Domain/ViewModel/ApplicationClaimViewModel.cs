namespace Auth.Domain.ViewModel
{
    public class ApplicationClaimViewModel
    {
        public int? Id { get; set; }
        public string RoleId { get; set; }
        public string ClaimValue { get; set; }

        public ApplicationClaimViewModel(string roleId, string claimValue)
        {
            RoleId = roleId;
            ClaimValue = claimValue;
        }
    }
}
