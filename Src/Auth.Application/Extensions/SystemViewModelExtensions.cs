using Auth.Domain.Entities;
using Auth.Domain.ViewModel;

namespace Auth.Application.Extensions
{
    public static class SystemViewModelExtensions
    {
        public static SystemEntity ToSystem(this SystemViewModel model)
        {
            return new SystemEntity 
            { 
                Id = model.Id, 
                Name = model.Name, 
                Url = model.Url 
            };
        }
    }
}
