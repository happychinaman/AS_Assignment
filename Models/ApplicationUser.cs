using Microsoft.AspNetCore.Identity;

namespace AS_Assignment.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? FullName { get; set; }

        public string? CreditCardNo { get; set; }

        public string? DeliveryAddress { get; set; }

        public string? ShippingAddress { get; set; }

        public DateTime? LastPasswordChangeDate { get; set; }

        public byte[]? Image { get; set; }
    }
}
