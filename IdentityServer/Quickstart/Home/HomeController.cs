using System.Threading.Tasks;
using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;

namespace IdentityServer.Quickstart.Home
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IWebHostEnvironment _environment;

        public HomeController(
            IIdentityServerInteractionService interaction,
            IWebHostEnvironment environment)
        {
            _interaction = interaction;
            _environment = environment;
        }
        
        // [HttpGet("mails")]
        // public async Task<IActionResult> SendMails([FromServices] IMailService mailService)
        // {
        //     await mailService.SendNewSeasonMail("26.3.", "27.3.");
        //     return Ok();
        // }

        public IActionResult Index()
        {
            return View();
        }

        /// <summary>
        /// Shows the error page
        /// </summary>
        public async Task<IActionResult> Error(string errorId)
        {
            var vm = new ErrorViewModel();

            // retrieve error details from identityserver
            var message = await _interaction.GetErrorContextAsync(errorId);
            if (message != null)
            {
                vm.Error = message;

                if (!_environment.IsDevelopment())
                {
                    // only show in development
                    message.ErrorDescription = null;
                }
            }

            return View("Error", vm);
        }
    }
}