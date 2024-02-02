using System.ComponentModel.DataAnnotations;

namespace AS_Assignment.ViewModels
{
    public class Register
    {
        [Required]
        [DataType(DataType.Text)]
        public string FullName { get; set; }

        [Required]
        [DataType(DataType.CreditCard)]
        [RegularExpression(@"^\d{16}$", ErrorMessage = "Invalid Credit Card Number (must be digits and 16 chars) ")]
        public string CreditCardNo { get; set; }

        [Required]
        [DataType(DataType.PhoneNumber)]
        [RegularExpression(@"^\d{8}$", ErrorMessage = "Invalid Mobile Number (must be digits and 8 chars)")]
        public string MobileNo { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string DeliveryAddress { get; set; }

        [Required]
        [DataType(DataType.Text)]
        public string ShippingAddress { get; set; }

        [Required]
        [DataType(DataType.EmailAddress)]
        [EmailAddress(ErrorMessage = "Invalid email address ")]
        public string Email { get; set; }

        //2.1 password complexity checks 2.3.server-side based check
        [Required]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{12,}$", ErrorMessage = "Password must contain at least one uppercase," +
        " one lowercase,one digit, one special character and minimum 12 chars.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Password and confirmation password does not match.")]
        public string ConfirmPassword { get; set; }

        //[FileExtensions(Extensions = "jpg,jpeg,png", ErrorMessage = "Invalid file format. Use jpg.")]
        public IFormFile ImageFile { get; set; }
    }
}
