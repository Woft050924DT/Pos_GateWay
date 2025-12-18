using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Pos_GateWay.Helper;
using Pos_GateWay.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace Pos_GateWay
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly AppSettings _appSettings;
        private readonly HdvContext _db;

        public JwtMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings, IConfiguration configuration)
        {
            _next = next;
            _appSettings = appSettings.Value;
            _db = new HdvContext(configuration);
        }

        public Task Invoke(HttpContext context)
        {
            // Thêm CORS headers
            context.Response.Headers.Add("Access-Control-Allow-Origin", "*");
            context.Response.Headers.Add("Access-Control-Expose-Headers", "*");

            // Kiểm tra nếu không phải endpoint login thì chuyển tiếp request
            if (!context.Request.Path.Equals("/api/login", StringComparison.Ordinal))
            {
                return _next(context);
            }

            // Xử lý login
            if (context.Request.Method.Equals("POST") && context.Request.HasFormContentType)
            {
                return GenerateToken(context);
            }

            context.Response.StatusCode = 400;
            return context.Response.WriteAsync("Bad request.");
        }

        public async Task GenerateToken(HttpContext context)
        {
            var username = context.Request.Form["Username"].ToString();
            var password = context.Request.Form["Password"].ToString();

            // Validate input
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                var errorResult = JsonConvert.SerializeObject(new
                {
                    code = (int)HttpStatusCode.BadRequest,
                    error = "Username và Password không được để trống"
                });
                await context.Response.WriteAsync(errorResult);
                return;
            }

            // Query user với thông tin Role - so sánh trực tiếp username, password và IsActive
            var user = (from u in _db.Users
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

            // Kiểm tra user tồn tại và password đúng
            if (user == null)
            {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                var result = JsonConvert.SerializeObject(new
                {
                    code = (int)HttpStatusCode.BadRequest,
                    error = "Tài khoản hoặc mật khẩu không đúng"
                });
                await context.Response.WriteAsync(result);
                return;
            }

            // Tạo JWT token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
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

            // Tạo response
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

            var serializerSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented
            };

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonConvert.SerializeObject(response, serializerSettings));
        }
    }
}