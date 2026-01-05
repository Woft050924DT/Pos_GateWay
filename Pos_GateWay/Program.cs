using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Pos_GateWay;
using Pos_GateWay.Helper;
using Pos_GateWay.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Load ocelot.json
builder.Configuration
    .SetBasePath(builder.Environment.ContentRootPath)
    .AddJsonFile("ocelot.json", optional: false, reloadOnChange: true);

const string defaultJwtSecret = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET_KEY_32_CHARS_MIN";

builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));
builder.Services.PostConfigure<AppSettings>(options =>
{
    if (string.IsNullOrWhiteSpace(options.Secret) || Encoding.UTF8.GetByteCount(options.Secret) < 32)
    {
        options.Secret = defaultJwtSecret;
    }
});

builder.Services.AddDbContext<HdvContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// ================= AUTHENTICATION (BẮT BUỘC) =================
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer("Bearer", options =>
    {
        var jwtSecret = builder.Configuration["AppSettings:Secret"] ?? defaultJwtSecret;
        if (Encoding.UTF8.GetByteCount(jwtSecret) < 32)
        {
            jwtSecret = defaultJwtSecret;
        }
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtSecret))
        };
    });

builder.Services.AddAuthorization();
// =============================================================

// Add Ocelot
builder.Services.AddOcelot(builder.Configuration);

// Swagger (chỉ test Gateway)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Swagger
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// ⚠️ THỨ TỰ RẤT QUAN TRỌNG
app.UseMiddleware<JwtMiddleware>();
app.UseAuthentication();
app.UseAuthorization();

// Ocelot middleware (LUÔN Ở CUỐI)
await app.UseOcelot();

app.Run();
