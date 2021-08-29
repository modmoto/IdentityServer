﻿using System;
using IdentityServer.Quickstart;
using IdentityServer.Quickstart.Account;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MongoDB.Driver;

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
                    options.EmitStaticAudienceClaim = true;
                })
                .AddInMemoryIdentityResources(Config.IdentityResources)
                .AddInMemoryApiScopes(Config.ApiScopes)
                .AddInMemoryClients(Config.Clients)
                .AddProfileService<ProfileService>();
            
            services.AddTransient<UserStore>();
            services.AddTransient<UserAccountRepository>();
            services.AddSingleton(_ =>
            {
                var mongoConnectionString = Environment.GetEnvironmentVariable("MONGO_DB_CONNECTION_STRING");
                return new MongoClient(mongoConnectionString);
            });
            
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
            
            // this is so caddy can forward to http and the openid config is fine
            app.Use((context, next) =>
            {
                context.Request.Scheme = "https";
                return next();
            });
            app.UseIdentityServer();
            app.UseAuthorization();
            
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
