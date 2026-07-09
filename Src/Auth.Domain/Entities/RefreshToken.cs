using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;
using System.Text.Json.Serialization;

namespace Auth.Domain.Entities
{
    public class RefreshToken
    {
        public RefreshToken()
        {
            Id = Guid.NewGuid();
            Token = Guid.NewGuid();
        }

        public Guid Id { get; set; }
        public required string UserName { get; set; }
        public Guid Token { get; set; }
        public required DateTime ExpirationDate { get; set; }

        public bool isValid() => 
            ExpirationDate.ToLocalTime() > DateTime.UtcNow;
    }
}
