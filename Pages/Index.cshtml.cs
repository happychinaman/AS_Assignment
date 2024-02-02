using AS_Assignment.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace AS_Assignment.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<ApplicationUser> userManager;
        
        //2.6 implement decryption
        private readonly IDataProtectionProvider dataProtectionProvider;

        //3.1. implement session
        private readonly IOptions<SessionOptions> sessionOptions;

        public IndexModel(
           ILogger<IndexModel> logger,
           UserManager<ApplicationUser> userManager,
        
           IDataProtectionProvider dataProtectionProvider, 
           IOptions<SessionOptions> sessionOptions)
        {
            _logger = logger;
            this.userManager = userManager;
            this.dataProtectionProvider = dataProtectionProvider;
            this.sessionOptions = sessionOptions;
        }

        public ApplicationUser UserInfo { get; set; }

        public void OnGet()
        {
            var user = userManager.GetUserAsync(User).Result;

            //3.1 store info in session
            HttpContext.Session.SetString("UserId", user.Id);
            HttpContext.Session.SetString("FullName", user.FullName);

            UserInfo = user;

            //2.6 decrypt data
            var encryptedFirstName = user.FullName;
            var unprotectedFirstName = UnprotectData(encryptedFirstName);

            var encryptedCreditCard = user.CreditCardNo;
            var unprotectedCreditCard = UnprotectData(encryptedCreditCard);
            //display 
            ViewData["DecryptedFullName"] = unprotectedFirstName;
            ViewData["DecryptedCreditCard"] = unprotectedCreditCard;
        }

        //2.6 decryption of data
        private string UnprotectData(string protectedData)
        {
            var protector = dataProtectionProvider.CreateProtector("YourPurpose");
            return protector.Unprotect(protectedData);
        }
    }

}