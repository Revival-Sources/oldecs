using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Collections.Generic;
﻿using System;
using Npgsql;
using System.Text.RegularExpressions;
using System.IO;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Reflection;
using System.Net.Http;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace Test
{
    public class Program
    {
        // public static Dictionary<string, string> assetMap = new Dictionary<string, string>();

        public static void Main(string[] args)
        {
            UpdateAssetMap();
            CreateHostBuilder(args).Build().Run();
        }
        public static Dictionary<string, string> assetMap = new Dictionary<string, string>();
        private static Queue<string> assetQueue = new Queue<string>();
        private static bool isProcessingQueue = false;

        private static List<int> staffList = new List<int> { 1,2,3,6 };

    // private static SemaphoreSlim semaphore = new SemaphoreSlim(1, 1); // Semaphore for rate limiting

    // Rest of your code...

    private static ConcurrentDictionary<string, SemaphoreSlim> assetLocks = new ConcurrentDictionary<string, SemaphoreSlim>();

    public void ConfigureServices(IServiceCollection services)
    {
        // Register the assetLocks dictionary as a singleton
        services.AddSingleton(assetLocks);
    }
    private static string GenerateRandomString(int length)
{
    using (var rng = new RNGCryptoServiceProvider())
    {
        var bytes = new byte[length];
        rng.GetBytes(bytes);

        var stringBuilder = new StringBuilder(length);

        foreach (var b in bytes)
        {
            stringBuilder.Append(b.ToString("X2"));
        }

        return stringBuilder.ToString();
    }
}


        public static async Task MigrateAsset(string assetId)
        {
            assetQueue.Enqueue(assetId);

            if (!isProcessingQueue)
            {
                isProcessingQueue = true;
                await ProcessAssetQueue();
            }
        }

        private static async Task ProcessAssetQueue()
        {
            while (assetQueue.Count > 0)
            {
                string assetId = assetQueue.Dequeue();
                Console.WriteLine($"Migrating {assetId}");
                var path = Path.Combine(Directory.GetCurrentDirectory(), "Assets", assetId);
                if (File.Exists(path))
                    continue;
                try
                {
                    string assetUrl = $"https://assetdelivery.roblox.com/v1/asset/?id={assetId}";

                    using (HttpClient client = new HttpClient())
                    {
                        // Download the asset from Roblox
                        HttpResponseMessage response = await client.GetAsync(assetUrl);

                        if (response.IsSuccessStatusCode)
                        {
                            byte[] assetData = await response.Content.ReadAsByteArrayAsync();

                            // Save the asset
                            string assetPath = Path.Combine(Directory.GetCurrentDirectory(), "Assets", assetId);
                            File.WriteAllBytes(assetPath, assetData);

                            Console.WriteLine($"Asset {assetId} migrated to {assetPath}");
                        }
                        else if (response.StatusCode == (System.Net.HttpStatusCode)429) // Rate limited
                        {
                            int retryAfterSeconds = GetRetryAfterSeconds(response);
                            if (retryAfterSeconds > 0)
                            {
                                await Task.Delay(retryAfterSeconds * 1000);
                                // Re-enqueue the asset for retry
                                assetQueue.Enqueue(assetId);
                            }
                        }
                        else
                        {
                            Console.WriteLine($"Failed to migrate asset {assetId}. Status code: {response.StatusCode}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"An error occurred while migrating asset {assetId}: {ex.Message}");
                }
            }

            isProcessingQueue = false;
        }

        private static int GetRetryAfterSeconds(HttpResponseMessage response)
        {
            if (response.Headers.TryGetValues("Retry-After", out var retryAfterValues))
            {
                if (int.TryParse(retryAfterValues?.FirstOrDefault(), out int retryAfterSeconds))
                {
                    return 1;
                }
            }

            // Custom handling of rate limit headers, if any

            return 1;
        }
        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
            
    
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.ConfigureServices(services =>
                    {
                        services.AddDbContext<ApplicationDbContext>(options =>
                        {
                            var connectionString = "Host=localhost;Database=bloxie;Username=postgres;Password=bloxie@";
                            options.UseNpgsql(connectionString);
                        });
                    });
                    webBuilder.UseUrls("http://localhost:4000"); // Set the desired URL(s) here

                    webBuilder.Configure(app =>
                    {
                        app.UseStaticFiles();

                        app.UseRouting();

                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapGet("/joinscript", async context => {
                                if (context.Request.Cookies.TryGetValue("OLDECS_SECURITY", out var cookieValue))
                                {
                                    char t = '"';
                            await context.Response.WriteAsync($"RobloxPlayerBeta.exe -a {t}https://www.oldecs.com/Login/Negotiate.ashx{t} -j {t}http://www.oldecs.com/game/join.ashx?cookie={cookieValue}{t} -t {t}{cookieValue}{t}");
                            }
                        else
                    {
                        await context.Response.WriteAsync("You are not logged in.");
                    }

                        });
                            endpoints.MapGet("/Asset/BodyColors.ashx", async context =>
                            {
                                // var username = context.Request.Query["username"];
                                var userid = context.Request.Query["userId"];
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "BodyColors.xml");
                                context.Response.ContentType = "application/xml";
                                await context.Response.SendFileAsync(filePath);
                            });
                            endpoints.MapGet("/Game/Join.ashx", async context => {
    if (!context.Request.Query.ContainsKey("cookie"))
    {
        context.Response.StatusCode = 400; // Bad Request
        await context.Response.WriteAsync("Cookie query is missing");
        return;
    }

    var cookieQuery = context.Request.Query["cookie"].ToString();
                                string format = true ? "--rbxsig%{0}%{1}" : "%{0}%{1}";
                                // var userid = context.Request.Query["userId"];
                                 var shaCSP = new SHA1CryptoServiceProvider();
                                 var rsaCSP = new RSACryptoServiceProvider();
                                                                     using (var scope = app.ApplicationServices.CreateScope())
                                    {
                                        
                                        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                                                var user = dbContext.Users.FirstOrDefault(u => u.cookie == cookieQuery);

        if (user == null)
        {
            context.Response.StatusCode = 404; // Not Found
            await context.Response.WriteAsync("User not found");
            return;
        }
                var username = user.username;
        var id = user.id;

                                        // var highestId = dbContext.Users.OrderByDescending(u => u.id).Select(u => u.id).FirstOrDefault();
                                        // var nextId = highestId + 1;
                                        // string script = File.ReadAllText(Path.Combine(Directory.GetCurrentDirectory(), "Pages", "join.ashx"));
            string script = "\r\n" + File.ReadAllText(Path.Combine(Directory.GetCurrentDirectory(), "Pages", "join.ashx"));
                            var fileContent = script;
                            byte[] signature = rsaCSP.SignData(Encoding.Default.GetBytes(script), shaCSP);
                             script = String.Format(format, Convert.ToBase64String(signature), script);
                            //  var updated2 = updated.Replace("id")
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "join.ashx");
                                // await context.Response.SendFileAsync(filePath);
                                script = script.Replace("USERNAMEHERE", username).Replace("USERIDHERE", id.ToString());
                                if (user.membership == null) {
                                    script = script.Replace("MEMBERSHIPTYPEHERE", "None");
                                } else {
                                script = script.Replace("MEMBERSHIPTYPEHERE", user.membership.ToString());
                                }
                                await context.Response.WriteAsync(script);
                              }
                            });
                            endpoints.MapGet("/Game/PlaceLauncher.ashx", async context => {
                                // var userid = context.Request.Query["userId"];
    if (!context.Request.Query.ContainsKey("cookie"))
    {
        context.Response.StatusCode = 400; // Bad Request
        await context.Response.WriteAsync("Cookie is missing");
        return;
    }

    var cookieQuery = context.Request.Query["cookie"].ToString();
    string updated = File.ReadAllText(Path.Combine(Directory.GetCurrentDirectory(), "Pages", "PlaceLauncher.ashx"));
    updated = updated.Replace("?cookie=cookie", $"?cookie={cookieQuery}");
    updated =updated.Replace("cookie=cookie", cookieQuery);
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "PlaceLauncher.ashx");
                                await context.Response.WriteAsync(updated);
                            });
                            endpoints.MapGet("/Login/Negotiate.ashx", async context => {
                                // var userid = context.Request.Query["userId"];
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "negotiate.ashx");
                                await context.Response.SendFileAsync(filePath);
                            });
                            endpoints.MapGet("/Setting/QuietGet/ClientAppSettings", async context => {
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "fflags.cshtml");
                                await context.Response.SendFileAsync(filePath);
                            });
                            endpoints.MapGet("/Setting/QuietGet/ClientSharedSettings", async context => {
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "fflags.cshtml");
                                await context.Response.SendFileAsync(filePath);
                            });
                            endpoints.MapGet("/Game/Visit.ashx", async context => {
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "visit.ashx");
                                await context.Response.SendFileAsync(filePath);
                            });
                            endpoints.MapGet("/game/validate-machine", async context => {
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "validatemachine.cshtml");
                                await context.Response.SendFileAsync(filePath);
                            });
                            endpoints.MapGet("/Game/GetCurrentUser.ashx", async context => {
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "currentuser.ashx");
                                await context.Response.SendFileAsync(filePath);
                            });
                            endpoints.MapGet("/Asset/CharacterFetch.ashx", async context =>
                            {
                                // var username = context.Request.Query["username"];
                                var userid = context.Request.Query["userId"];
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "fetch.cshtml");
                                var fileContent = await File.ReadAllTextAsync(filePath);
                                // if (userid == "") {
                                    // await context.Response.WriteAsync(fileContent);
                                    // return;
                                // }
                                var updatedContent = fileContent.Replace("?userId=0", "?userId=" + userid);
                                // context.Response.ContentType = "application/xml";
                                await context.Response.WriteAsync(updatedContent);
                                // }
                                // var updatedContent = fileContent;
                                // await context.Response.SendFileAsync(filePath);
                            });
            endpoints.MapGet("/asset", async context =>
            {
                var id = context.Request.Query["id"];

                // Update the asset map before accessing it
                // UpdateAssetMap();

                // Acquire a lock for the asset ID
                var assetLock = assetLocks.GetOrAdd(id, new SemaphoreSlim(1));
                await assetLock.WaitAsync();
                await MigrateAsset(id);

                try
                {
                     if (assetMap.TryGetValue(id, out string assetName2)) {

                                        var filePath2 = Path.Combine(Directory.GetCurrentDirectory(), "Assets", assetName2);
                    if (File.Exists(filePath2)) {
                            context.Response.ContentType = "application/octet-stream";
                            await context.Response.SendFileAsync(filePath2);
                            return;
                    } else {
                        await MigrateAsset(id);
                    }
                     }
                     await MigrateAsset(id);
                    // await Task.Delay(1);

                    // Get the file name for the given ID from the assetMap
                    if (assetMap.TryGetValue(id, out string assetName))
                    {
                        var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Assets", assetName);
                        if (File.Exists(filePath))
                        {
                            context.Response.ContentType = "application/octet-stream";
                            await context.Response.SendFileAsync(filePath);
                        }
                        else
                        {
                            await MigrateAsset(id);
                            // context.Response.Redirect($"https://assetdelivery.roblox.com/v1/asset/?id={id}");
                        }
                    }
                    else
                    {
                    var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Assets", id);
                    if (assetMap.TryGetValue(id, out string name))
                    {
                        // var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Assets", name);
                        if (File.Exists(filePath))
                        {
                            context.Response.ContentType = "application/octet-stream";
                            await context.Response.SendFileAsync(filePath);
                        }
                    }
                        else {
                        // context.Response.StatusCode = 404;
                    // await MigrateAsset(assetName2);
                    await MigrateAsset(id);
                        if (File.Exists(filePath)) {
                            context.Response.ContentType = "application/octet-stream";
                            await context.Response.SendFileAsync(filePath);
                            }
                        else {
                    //  await MigrateAsset(assetName2);
                    await MigrateAsset(id);
                             if (File.Exists(filePath)) {
                            context.Response.ContentType = "application/octet-stream";
                            await context.Response.SendFileAsync(filePath);
                            } else {
                            context.Response.StatusCode = 404;
                            // context.Response.Redirect($"https://assetdelivery.roblox.com/v1/asset/?id={id}");
                            await context.Response.WriteAsync("Asset could not be migrated, or it doesn't exist.");
                                }
                        }
                        // await context.Response.WriteAsync("Asset not found");
                        }
                        // var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Assets", assetName);
                        // if (File.Exists(filePath))
                        // {
                        //     context.Response.ContentType = "application/octet-stream";
                        //     await context.Response.SendFileAsync(filePath);
                        // }
                    }
                }
                finally
                {
                    assetLock.Release();
                }
            });
        // });
                    endpoints.MapGet("/Game/LuaWebService/HandleSocialRequest.ashx", async context => {
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "luawebservice.ashx");
                                var playerid = context.Request.Query["playerid"];
                                var filePath2 = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "group.ashx");
                                var filecontent = File.ReadAllText(Path.Combine(Directory.GetCurrentDirectory(), "Pages", "luawebservice.ashx"));
                                context.Response.ContentType = "application/xml";
                                var method = context.Request.Query["method"];
                                if (method == "GetGroupRank") {
                                    await context.Response.SendFileAsync(filePath2);
                                } else if (method == "IsInGroup"){
                                    if (staffList.Contains(int.Parse(playerid))) {
                                        filecontent = filecontent.Replace("false", "true");
                                        await context.Response.WriteAsync(filecontent); 
                                        return;
                                    } else {
                                        await context.Response.SendFileAsync(filePath);
                                    }
                                }
                    });
                    endpoints.MapGet("/logout", async context => {
                        context.Response.Cookies.Delete("OLDECS_SECURITY");
                        context.Response.Redirect("/login");
                    });
                    endpoints.MapGet("/ownership/hasasset/{**path}", async context =>{
                        await context.Response.WriteAsync("true");
                    });
                    endpoints.MapGet("/Thumbs/Avatar.ashx", async context => {
                                var id = context.Request.Query["userId"];
                                context.Response.Redirect("/static/img/placeholder.png");
                    });
                    endpoints.MapGet("/Thumbs/Asset.ashx", async context => {
                                var id = context.Request.Query["userId"];
                                context.Response.Redirect("/static/img/placeholder.png");
                    });
                    endpoints.MapGet("/productinfo", async context => {
                                var id = context.Request.Query["id"];
                                // context.Response.Redirect("/static/img/placeholder.png");
                    });
                    endpoints.MapGet("/static/img/placeholder.png", async context => {
                         var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Avatars", "placeholder.png");
                                await context.Response.SendFileAsync(filePath);
                    });
                            // endpoints.MapGet("/", async context =>
                    endpoints.MapGet("/", async context =>
                            {
                                if (context.Request.Cookies.TryGetValue("OLDECS_SECURITY", out var cookieValue))
                                {
                                    if (cookieValue != null) {
                                        context.Response.Redirect("/home");
                                    }
                                }
                                    
    var username = context.Request.Query["username"].ToString();
    var password = context.Request.Query["password"].ToString();
                                Console.WriteLine($"Signing up using: username {username} password {password}");
                                
                                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                                {
                                    using (var scope = app.ApplicationServices.CreateScope())
                                    {
                                        var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                                        var userd = dbContext.Users.FirstOrDefault(u => u.username == username);
                                        // if (dbContext.Users.Any(username)) {
                                            // return;
                                        // }
if (userd != null && userd.username == username || userd != null && userd.username.ToString().ToLower().Contains("ROBLOX"))
{
    await context.Response.WriteAsync("Could not make account: User already exists");
    return;
}
string pattern = @"\p{IsBasicLatin}*$";

// Use Regex.IsMatch to check if the username contains only Basic Latin characters
bool containsUnicode = !Regex.IsMatch(username, pattern);
if (containsUnicode)
{
    // Handle the case when Unicode characters are present
    // For example, display an error message or reject the username
    // Console.WriteLine("Username contains Unicode characters. Please choose a different username.");
    await context.Response.WriteAsync("Unicode detected.");
    return;
}
                                        var highestId = dbContext.Users.OrderByDescending(u => u.id).Select(u => u.id).FirstOrDefault();
                                        var nextId = highestId + 1;
                    var cookieOptions = new CookieOptions
                    {
        // Set other properties like expiration, secure, etc.
                  Expires = DateTime.Now.AddDays(100),
                    Secure = true,
                        HttpOnly = true
                        };
                        var cookie = GenerateRandomString(500);
                        Console.WriteLine($"Cookie: {cookie}");
                        context.Response.Cookies.Append("OLDECS_SECURITY", cookie, cookieOptions);
                        if (username.Contains(" ") || username.Any(char.IsWhiteSpace)) {
                            await context.Response.WriteAsync("Sorry, you have spaces in your username.");
                            return;
                        };
                                        var user = new Users
                                        {
                                            id = nextId,
                                            username = username,
                                            password = password,
                                            cookie = cookie,
                                            membership = "None",
                                            robux = 100,
                                            tix = 0
                                        };

                                        dbContext.Users.Add(user);
                                        dbContext.SaveChanges();
                                        System.Console.WriteLine("User created");
                                        context.Response.Redirect("/home");
                                    }
                                }
                                // context.Response.Redirect("/home");
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "signup.cshtml");
                                await context.Response.SendFileAsync(filePath);
                            });
endpoints.MapGet("/login", async context =>
{
    var username = context.Request.Query["username"].ToString();
    var password = context.Request.Query["password"].ToString();
    Console.WriteLine($"Logging in using: username {username} password {password}");

    if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
    {
        using (var scope = app.ApplicationServices.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            // Check if the provided username and password match a user in the database
            var user = dbContext.Users.FirstOrDefault(u => u.username == username && u.password == password);

            if (user != null)
            {
                // Retrieve the cookie from the user column
                // user.coo
                var cookie = user.cookie;
                    var cookieOptions = new CookieOptions
                    {
        // Set other properties like expiration, secure, etc.
                  Expires = DateTime.Now.AddDays(100),
                    Secure = true,
                        HttpOnly = true
                        };
                // Set the cookie in the response
                context.Response.Cookies.Append("OLDECS_SECURITY", cookie, cookieOptions);
                context.Response.Redirect("/home");
                Console.WriteLine("Set Cookie");
            }
        }
    }

    var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "login.cshtml");
    await context.Response.SendFileAsync(filePath);
});
endpoints.MapGet("/api/cookie", async context =>
{
    if (context.Request.Cookies.TryGetValue("OLDECS_SECURITY", out var cookieValue))
    {
        await context.Response.WriteAsync($"{cookieValue}");
    }
    else
    {
        await context.Response.WriteAsync("You are not logged in.");
    }
});
endpoints.MapGet("/api/userid", async context => {
     if (context.Request.Cookies.TryGetValue("OLDECS_SECURITY", out var cookieValue))
    {
        // await context.Response.WriteAsync($"{cookieValue}");
                using (var scope = app.ApplicationServices.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var user = dbContext.Users.FirstOrDefault(u => u.cookie == cookieValue);
            await context.Response.WriteAsync(user.id.ToString());
        }
    }
    else
    {
        await context.Response.WriteAsync("You are not logged in.");
    }
    // var user = dbContext.Users.FirstOrDefault(u => u.cookie == cookieQuery);
});
endpoints.MapGet("/api/staff", async context => {
     if (context.Request.Cookies.TryGetValue("OLDECS_SECURITY", out var cookieValue))
    {
        // await context.Response.WriteAsync($"{cookieValue}");
                using (var scope = app.ApplicationServices.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var user = dbContext.Users.FirstOrDefault(u => u.cookie == cookieValue);
            // await context.Response.WriteAsync(user.id.ToString());
            if (staffList.Contains(user.id)) {
                await context.Response.WriteAsync("is staff: true");
            } else {
await context.Response.WriteAsync("is staff: false");
            }
        }
    }
    else
    {
        await context.Response.WriteAsync("You are not logged in.");
    }
    // var user = dbContext.Users.FirstOrDefault(u => u.cookie == cookieQuery);
});
                        // });
                    // });
                            endpoints.MapGet("/game/players/{**path}", async context =>
                            {
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "gameplayers.ashx");
                                await context.Response.SendFileAsync(filePath);
                            });
                            endpoints.MapGet("/users/{**path}", async context =>
                            {
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "canmanage.ashx");
                                await context.Response.SendFileAsync(filePath);
                            });
                            endpoints.MapGet("/GetAllowedMD5Hashes", async context =>
                            {
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "allowedmd5hashes.ashx");
                                await context.Response.SendFileAsync(filePath);
                            });
                            endpoints.MapGet("/home", async context => {
                                // await context.Response.WriteAsync("Coming soon.");
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "home.cshtml");
                                if (context.Request.Cookies.TryGetValue("OLDECS_SECURITY", out var cookieValue))
                                {
                                    if (cookieValue == null) {
                                        Console.WriteLine("Redirecting");
                                        context.Response.Redirect("/login");
                                    }
                                    using (var scope = app.ApplicationServices.CreateScope())
                                    {
                                        
                                    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                                    var user = dbContext.Users.FirstOrDefault(u => u.cookie == cookieValue);
                                    if (user != null) {
                                    var filecontent = File.ReadAllText(Path.Combine(Directory.GetCurrentDirectory(), "Pages", "home.cshtml"));
                                    filecontent = filecontent.Replace("Username", user.username);
                                    if (staffList.Contains(user.id)) {
                                        filecontent = filecontent.Replace("Membership", "Administrator");
                                    }
                                    else if (user.membership == "OutrageousBuildersClub") {
                                        filecontent = filecontent.Replace("Membership", "OBC");
                                    
                                    } else if (user.membership == "TurboBuildersClub") {
                                        filecontent = filecontent.Replace("Membership", "TBC");
                                    } else if (user.membership == "BuildersClub") {
                                        filecontent = filecontent.Replace("Membership", "BC");
                                    } else {
                                        filecontent = filecontent.Replace("(Membership)", "");
                                    }
                                    filecontent = filecontent.Replace("ROBUXHERE", user.robux.ToString());
                                    filecontent = filecontent.Replace("TIXHERE", user.tix.ToString());
                                    await context.Response.WriteAsync(filecontent);
                                    } else {
                                        Console.WriteLine("Redirecting");
                                        context.Response.Redirect("/login");
                                    }
                                    }
                                } else {
                                    Console.WriteLine("Redirecting");
                                    context.Response.Redirect("/login");
                                }
                            });
                            endpoints.MapGet("/membership", async context => {
                                var filePath = Path.Combine(Directory.GetCurrentDirectory(), "Pages", "membership.cshtml");
                        if (context.Request.Cookies.TryGetValue("OLDECS_SECURITY", out var cookieValue))
                                {
                                    using (var scope = app.ApplicationServices.CreateScope())
                                    {
                                     var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                                    var user = dbContext.Users.FirstOrDefault(u => u.cookie == cookieValue);
                            await context.Response.SendFileAsync(filePath);
                                    }
                                    }
                            });
                        });
                    });
                });

        private static void UpdateAssetMap()
        {
            var assetFolder = Path.Combine(Directory.GetCurrentDirectory(), "Assets");
            var files = Directory.GetFiles(assetFolder);

            assetMap.Clear();

            foreach (var file in files)
            {
                var fileName = Path.GetFileName(file);
                var fileId = Path.GetFileNameWithoutExtension(fileName);

                assetMap[fileId] = fileName;
            }
        }
            public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {

        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Users>().ToTable("users"); // dont make it Users or User or it wil break :(((
            base.OnModelCreating(modelBuilder);
        }

        public DbSet<Users> Users { get; set; }
    }
        public class Users
    {
        public int id { get; set; }
        public string username { get; set; }
        public string password { get; set; }
        public string cookie { get; set; }
        public string membership { get; set; }
        public int robux { get; set; }
        public int tix { get; set; }
    }   
    }
}
