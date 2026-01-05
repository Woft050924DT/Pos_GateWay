using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Pos_GateWay.Helper;
using Pos_GateWay.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace Pos_GateWay
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly AppSettings _appSettings;
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            WriteIndented = true
        };

        public JwtMiddleware(
        RequestDelegate next,
        IOptions<AppSettings> appSettings)
        {
            _next = next;
            _appSettings = appSettings.Value;
        }

        public Task Invoke(HttpContext context, HdvContext db)
        {
            context.Response.Headers.TryAdd("Access-Control-Allow-Origin", "*");
            context.Response.Headers.TryAdd("Access-Control-Expose-Headers", "*");

            if (!context.Request.Path.Equals("/api/login", StringComparison.OrdinalIgnoreCase))
            {
                return _next(context);
            }

            if (context.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                && (context.Request.HasFormContentType
                    || context.Request.ContentType?.Contains("application/json", StringComparison.OrdinalIgnoreCase) == true))
            {
                return GenerateToken(context, db);
            }

            context.Response.StatusCode = 400;
            return context.Response.WriteAsync("Bad request.");
        }

        private async Task<(string? Username, string? Password)> ReadCredentials(HttpContext context)
        {
            if (context.Request.HasFormContentType)
            {
                var form = await context.Request.ReadFormAsync();
                var username = form["username"].ToString();
                var password = form["password"].ToString();

                if (string.IsNullOrWhiteSpace(username))
                {
                    username = form["Username"].ToString();
                }

                if (string.IsNullOrWhiteSpace(password))
                {
                    password = form["Password"].ToString();
                }

                return (username, password);
            }

            if (context.Request.ContentType?.Contains("application/json", StringComparison.OrdinalIgnoreCase) == true)
            {
                try
                {
                    var login = await JsonSerializer.DeserializeAsync<LoginRequest>(context.Request.Body, JsonOptions);
                    return (login?.Username, login?.Password);
                }
                catch
                {
                    return (null, null);
                }
            }

            return (null, null);
        }

        private async Task WriteJson(HttpContext context, int statusCode, object payload)
        {
            context.Response.StatusCode = statusCode;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(payload, JsonOptions));
        }

        public async Task GenerateToken(HttpContext context, HdvContext db)
        {
            var (username, password) = await ReadCredentials(context);
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                await WriteJson(context, (int)HttpStatusCode.BadRequest, new
                {
                    code = (int)HttpStatusCode.BadRequest,
                    error = "Username và Password không được để trống"
                });
                return;
            }

            if (string.IsNullOrWhiteSpace(_appSettings.Secret))
            {
                await WriteJson(context, (int)HttpStatusCode.InternalServerError, new
                {
                    code = (int)HttpStatusCode.InternalServerError,
                    error = "JWT Secret chưa được cấu hình"
                });
                return;
            }

            if (Encoding.UTF8.GetByteCount(_appSettings.Secret) < 32)
            {
                await WriteJson(context, (int)HttpStatusCode.InternalServerError, new
                {
                    code = (int)HttpStatusCode.InternalServerError,
                    error = "JWT Secret phải có tối thiểu 32 ký tự"
                });
                return;
            }

            var user = (from u in db.Users
                        where u.Username == username
                           && u.PasswordHash == password
                           && u.IsActive == true
                        select new
                        {
                            UserId = u.UserId,
                            Username = u.Username,
                            FullName = u.FullName,
                            Phone = u.Phone,
                            RoleId = u.RoleId,
                            RoleName = u.Role != null ? u.Role.RoleName : "User"
                        }).SingleOrDefault();

            if (user == null)
            {
                await WriteJson(context, (int)HttpStatusCode.BadRequest, new
                {
                    code = (int)HttpStatusCode.BadRequest,
                    error = "Tài khoản hoặc mật khẩu không đúng"
                });
                return;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                    new Claim(ClaimTypes.Name, user.FullName),
                    new Claim(ClaimTypes.Role, user.RoleName),
                    new Claim("Username", user.Username)
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            var response = new
            {
                UserId = user.UserId,
                Username = user.Username,
                FullName = user.FullName,
                Phone = user.Phone,
                Role = user.RoleName,
                Token = tokenString,
                ExpiresAt = tokenDescriptor.Expires
            };

            await WriteJson(context, (int)HttpStatusCode.OK, response);
        }

        private sealed class LoginRequest
        {
            public string? Username { get; set; }
            public string? Password { get; set; }
        }
    }
}
