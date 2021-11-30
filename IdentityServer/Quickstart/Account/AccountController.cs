using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AspNetCore.Identity.Mongo.Model;
using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using IdentityModel;
using IdentityServer.Quickstart.Mail;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityServer.Quickstart.Account
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly IUserStore<MongoUser> _userStore;
        private readonly UserManager<MongoUser> _userManager;
        private readonly ILookupNormalizer _lookupNormalizer;
        private readonly IMailService _mailService;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IIdentityProviderStore _identityProviderStore;
        private readonly IEventService _events;

        public AccountController(
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IIdentityProviderStore identityProviderStore,
            IEventService events,
            IUserStore<MongoUser> userStore, 
            UserManager<MongoUser> userManager,
            ILookupNormalizer lookupNormalizer,
            IMailService mailService)
        {
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _identityProviderStore = identityProviderStore;
            _events = events;
            _userStore = userStore;
            _userManager = userManager;
            _lookupNormalizer = lookupNormalizer;
            _mailService = mailService;
        }

        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl, string email)
        {
            var vm = await BuildLoginViewModelAsync(returnUrl, email);

            if (vm.IsExternalLoginOnly)
            {
                return RedirectToAction("Challenge", "External", new { scheme = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }
        
        [HttpGet]
        public IActionResult Register(string returnUrl, MailState mailSent)
        {
            var registerInputModel = new RegisterInputModel
            {
                ReturnUrl = returnUrl,
                EmailSent = mailSent
            };

            return View(registerInputModel);
        }
        
        [HttpGet]
        public async Task<IActionResult> ConfirmMail(string returnUrl, string email, string confirmToken, MailState mailSent)
        {
            if (mailSent != MailState.Sent) 
            {
                var codeDecoded = Decode(confirmToken);
                var returnUrlDecoded = Decode(returnUrl);
                var emailDecoded = Decode(email);
                var user = await _userManager.FindByEmailAsync(emailDecoded);
                var model = new ConfirmViewModel()
                {
                    ReturnUrl = returnUrlDecoded,
                    Email = email
                };
            
                if (user != null)
                {
                    var result = await _userManager.ConfirmEmailAsync(user, codeDecoded);
                    if (result.Succeeded)
                    {
                        model.ConfirmedMail = true;    
                    }
                
                    return View(model);
                }
            }
            
            return View(new ConfirmViewModel { MailSent = mailSent });
        }

        [HttpPost]
        public IActionResult ConfirmMail(ConfirmViewModel viewModel)
        {
            var loginViewModel = new LoginViewModel
            {
                Email = Decode(viewModel.Email),
                ReturnUrl = Decode(viewModel.ReturnUrl)
            };
            return RedirectToAction("Login", loginViewModel);
        }
        
        [HttpGet]
        public IActionResult ForgotPassword(string returnUrl, string email)
        {
            var model = new MailInputModel
            {
                Email = email,
                ReturnUrl = returnUrl
            };

            return View(model);
        }
        
        [HttpGet]
        public IActionResult ResetPassword(string returnUrl, string email, string resetToken)
        {
            var codeDecoded = Decode(resetToken);
            var returnUrlDecoded = Decode(returnUrl);

            var model = new ResetPasswordInputModel
            {
                Email = email,
                ReturnUrl = returnUrlDecoded,
                PasswordResetToken = codeDecoded
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordInputModel model)
        {
            var returnUrl = Decode(model.ReturnUrl);
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);

            if (model.NewPassword != model.RepeatPassword)
            {
                ModelState.AddModelError("PasswordsNotEqual", "Passwords are not equal");
            }

            if (ModelState.IsValid)
            {
                var email = Decode(model.Email);
                var user = await _userManager.FindByEmailAsync(email);
                if (user != null)
                {
                    var passwordChangeResult = await _userManager.ResetPasswordAsync(user, model.PasswordResetToken, model.NewPassword);
                    if (passwordChangeResult.Succeeded)
                    {
                        var loginInputModel = new LoginInputModel
                        {
                            Password = model.NewPassword,
                            Email = email,
                            ReturnUrl = returnUrl
                        };
                        return await LoginUser(loginInputModel, user, context);
                    }

                    AddErrorsToModelState(passwordChangeResult);
                }
            }
            
            return View(model);
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(MailInputModel model, string button)
        {
            if (button == "cancel")
            {
                var login = new LoginInputModel
                {
                    ReturnUrl = model.ReturnUrl
                };
                return RedirectToAction("Login", login);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            var newModel = new MailInputModel
            {
                ReturnUrl = model.ReturnUrl,
            };
            
            if (user != null)
            {
                var newPwToken = await _userManager.GeneratePasswordResetTokenAsync(user);
                var state = await _mailService.SendMail(model.Email, new ResetPasswordMailModel(newPwToken, model.ReturnUrl, model.Email));
                newModel.EmailSent = state;
                return View(newModel);
            }

            newModel.EmailSent = MailState.Sent;
            return View(newModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterInputModel model, string button)
        {
            if (button == "cancel")
            {
                var login = new LoginInputModel
                {
                    ReturnUrl = model.ReturnUrl
                };
                return RedirectToAction("Login", login);
            }
            
            if (model.Password != model.RepeatPassword)
            {
                ModelState.AddModelError("PasswordsNotEqual", "Passwords are not equal");
            }
            
            if (ModelState.IsValid)
            {
                var claimsToAdd = new List<IdentityUserClaim<string>> {
                    new()
                    {
                        ClaimType = JwtClaimTypes.GivenName,
                        ClaimValue = model.Name
                    }
                };
                var account = new MongoUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    Claims = claimsToAdd,
                };

                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    var result = await _userManager.CreateAsync(account, model.Password);
                    if (result.Succeeded)
                    {
                        var userCreated = await _userManager.FindByEmailAsync(model.Email);
                        return await SendRegisterMail(model, userCreated);
                    }
                    
                    AddErrorsToModelState(result);
                }
                else
                {
                    if (!user.EmailConfirmed)
                    {
                        return await SendRegisterMail(model, user);
                    }
                    
                    ModelState.AddModelError("UserExists", "This email is already registered, try logging in or resetting the password");
                }
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            if (button == "register")
            {
                var register = new RegisterInputModel
                {
                    ReturnUrl = model.ReturnUrl
                };
                return RedirectToAction("Register", register);
            }
            
            if (button == "forgot-pw")
            {
                var register = new MailInputModel
                {
                    Email = model.Email,
                    ReturnUrl = model.ReturnUrl
                };
                return RedirectToAction("ForgotPassword", register);
            }
            
            if (button == "login")
            {
                var mail = _lookupNormalizer.NormalizeName(model.Email);
                var user = await _userStore.FindByNameAsync(mail, CancellationToken.None);
                var identityResult = await _userManager.CheckPasswordAsync(user, model.Password);
                
                if (identityResult)
                {
                    return await LoginUser(model, user, context);
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Email, "invalid credentials", clientId:context?.Client.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
                ModelState.Remove("Email");
            }

            var vm = await BuildLoginViewModelAsync(model.ReturnUrl, model.Email);
            return View(vm);
        }

        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                return await Logout(vm);
            }

            return View(vm);
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                await HttpContext.SignOutAsync();
                await HttpContext.SignOutAsync("Identity.Application");

                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            if (vm.TriggerExternalSignout)
            {
                var url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return Redirect(vm.PostLogoutRedirectUri ?? "/");
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }
        
        private async Task<IActionResult> LoginUser(LoginInputModel model, MongoUser user, AuthorizationRequest context)
        {
            await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id.ToString(), user.UserName, clientId: context?.Client.ClientId));

            var props = new AuthenticationProperties
            {
                IsPersistent = true,
                AllowRefresh = true,
                ExpiresUtc = DateTimeOffset.UtcNow.Add(TimeSpan.FromDays(30))
            };

            var isuser = new IdentityServerUser(user.Id.ToString())
            {
                DisplayName = user.UserName,
            };

            await HttpContext.SignInAsync(isuser, props);

            if (context != null)
            {
                if (context.IsNativeClient())
                {
                    return this.LoadingPage("Redirect", model.ReturnUrl);
                }

                return Redirect(model.ReturnUrl);
            }

            if (Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            if (string.IsNullOrEmpty(model.ReturnUrl))
            {
                return Redirect("~/");
            }

            throw new Exception("invalid return URL");
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl, string email)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Email = email,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var dyanmicSchemes = (await _identityProviderStore.GetAllSchemeNamesAsync())
                .Where(x => x.Enabled)
                .Select(x => new ExternalProvider
                {
                    AuthenticationScheme = x.Scheme,
                    DisplayName = x.DisplayName
                });
            providers.AddRange(dyanmicSchemes);

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                ExternalProviders = providers.ToArray(),
                Email = email,
            };
        }
        
        private void AddErrorsToModelState(IdentityResult result)
        {
            foreach (var identityError in result.Errors)
            {
                ModelState.AddModelError(identityError.Code, identityError.Description);
            }
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            return vm;
        }
        
        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
        
        private static string Encode(string resetToken)
        {
            var tokenGeneratedBytes = Encoding.UTF8.GetBytes(resetToken);
            var codeEncoded = WebEncoders.Base64UrlEncode(tokenGeneratedBytes);
            return codeEncoded;
        }
        
        private static string Decode(string resetToken)
        {
            var codeDecodedBytes = WebEncoders.Base64UrlDecode(resetToken);
            var codeDecoded = Encoding.UTF8.GetString(codeDecodedBytes);
            return codeDecoded;
        }
        
        
        private async Task<IActionResult> SendRegisterMail(RegisterInputModel model, MongoUser user)
        {
            var newEmailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            var result = await _mailService.SendMail(model.Email, new NewAccountMail(model.Name, newEmailToken, model.ReturnUrl, model.Email));   
            var confirmViewModel = new ConfirmViewModel()
            {
                Email = model.Email,
                ReturnUrl = model.ReturnUrl,
                MailSent = result
            };

            if (result == MailState.Error)
            {
                ModelState.AddModelError("SendingMailFailed", "Email confirmation failed, please try again later or contact support!");
                return View(model);
            }
            
            return RedirectToAction("ConfirmMail", confirmViewModel);
        }
    }
}
