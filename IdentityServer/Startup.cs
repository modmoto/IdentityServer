using System;
using IdentityServer.Quickstart;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace IdentityServer
{
    public class Startup
    {
        public IWebHostEnvironment WebEnvironment { get; }

        public Startup(IWebHostEnvironment webEnvironment)
        {
            WebEnvironment = webEnvironment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            
            services.AddIdentityServer(options =>
                {
                    options.IssuerUri = $"https://{Environment.GetEnvironmentVariable("IDENTITY_BASE_URI")}";
                    options.EmitStaticAudienceClaim = true;
                })
                .AddInMemoryIdentityResources(Config.IdentityResources)
                .AddInMemoryApiScopes(Config.ApiScopes)
                .AddTestUsers(TestUsers.Users)
                .AddInMemoryClients(Config.Clients);
            
            // services.AddAuthentication()
            //     .AddGoogle("Google", options =>
            //     {
            //         options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
            //
            //         options.ClientId = "<insert here>";
            //         options.ClientSecret = "<insert here>";
            //     });
        }

        public void Configure(IApplicationBuilder app)
        {
            if (WebEnvironment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            
            app.UseStaticFiles();
            app.UseRouting();
            
            app.UseIdentityServer();
            app.UseAuthorization();
            
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
