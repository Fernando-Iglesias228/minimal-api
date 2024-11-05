using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MinimalApi.Dominio.Enums;
using MinimalApi.Dominio.ModelViews;
using MinimalApi.Dominio.DTOs;
using MinimalApi.Dominio.Entidades;
using MinimalApi.Dominio.Interfaces;
using MinimalApi.Dominio.Servicos;
using MinimalApi.Infraestrutura.Db;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
        key = Configuration.GetSection("Jwt").ToString() ?? "";
    }

    private string key = "";
    public IConfiguration Configuration { get;set; } = default!;

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(option => {
            option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(option => {
            option.TokenValidationParameters = new TokenValidationParameters{
                ValidateLifetime = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                ValidateIssuer = false,
                ValidateAudience = false
            };
        });

        services.AddAuthorization();

        services.AddScoped<IAdministradorServico, AdministradorServico>(); 
        services.AddScoped<IVeiculoServico, VeiculoServico>(); 

        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(options => {
            options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme{
                Name = "Authorization",
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "Jwt",
                In = ParameterLocation.Header,
                Description = "Insira o token JWT:"
            });

            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme{
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    new string[] {}
                }
            });
        });

        services.AddDbContext<DbContexto>(options =>{
            options.UseMySql(
                Configuration.GetConnectionString("mysql"),
                ServerVersion.AutoDetect(Configuration.GetConnectionString("mysql"))
            );
        });

        services.AddCors(options =>
        {
            options.AddDefaultPolicy(
                builder =>
                {
                    builder.AllowAnyOrigin()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                });
        });
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {    
        app.UseSwagger();
        app.UseSwaggerUI();

        app.UseRouting();
        
        app.UseAuthentication();
        app.UseAuthorization();

        app.UseCors();


        app.UseEndpoints(endpoints => {
            #region Home
            endpoints.MapGet("/", () => Results.Json(new Home())).WithTags("Home").AllowAnonymous();
            #endregion

            #region Administradores
            string GerarTokenJWT(Administrador administrador){
                if(string.IsNullOrEmpty(key)) return string.Empty;

                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                var claims = new List<Claim>(){
                    new Claim("Email", administrador.Email),
                    new Claim("Perfil", administrador.Perfil),
                    new Claim(ClaimTypes.Role, administrador.Perfil)
                };

                var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: credentials
                );

                return new JwtSecurityTokenHandler().WriteToken(token);
            }

            endpoints.MapPost("/administradores/login", ([FromBody] LoginDTO loginDTO, IAdministradorServico administradorServico) => {
                var adm = administradorServico.Login(loginDTO);
                if(adm != null)
                {
                    string token = GerarTokenJWT(adm);

                    return Results.Ok(new AdministradorLogado
                    {
                        Email = adm.Email,
                        Perfil = adm.Perfil,
                        Token = token
                    });
                }
                else{
                    return Results.Unauthorized();
                }
            }).WithTags("Administradores").AllowAnonymous();

            endpoints.MapPost("/administradores", ([FromBody] AdministradorDTO administradorDTO, IAdministradorServico administradorServico) => {
                var validacao = new ErrosDeValidacao{
                    Mensagens = new List<string>()
                };

                if(string.IsNullOrEmpty(administradorDTO.Email))
                    validacao.Mensagens.Add("O email não pode ser vazio");
                if(string.IsNullOrEmpty(administradorDTO.Senha))
                    validacao.Mensagens.Add("A senha não pode ser vazia");
                if(administradorDTO.Perfil == null)
                    validacao.Mensagens.Add("O perfil não pode ser vazio");

                if(validacao.Mensagens.Count() > 0){
                    return Results.BadRequest(validacao);
                }

                var administrador = new Administrador {
                    Email = administradorDTO.Email,
                    Senha = administradorDTO.Senha,
                    Perfil = administradorDTO.Perfil.ToString() ?? Perfil.Editor.ToString()
                };
                administradorServico.Incluir(administrador);

                return Results.Created($"/administrador/{administrador.Id}", administrador);
            }).WithTags("Administradores").RequireAuthorization(new AuthorizeAttribute{ Roles = "Adm" });

            endpoints.MapGet("/administradores", ([FromQuery] int? pagina, IAdministradorServico administradorServico) => {
                var adms = new List<AdministradorMV>();
                var administradores = administradorServico.Todos(pagina);
                foreach(var adm in administradores){
                    adms.Add(new AdministradorMV{
                        Id = adm.Id,
                        Email = adm.Email,
                        Perfil = adm.Perfil
                    });
                }
                return Results.Ok(adms);
            }).WithTags("Administradores").RequireAuthorization(new AuthorizeAttribute{ Roles = "Adm" });

            endpoints.MapGet("/administradores/{id}", ([FromQuery] int id, IAdministradorServico administradorServico) => {
                var adm = administradorServico.BuscaPorId(id);
                if(adm == null) return Results.NotFound();

                var administrador = new AdministradorMV{
                        Id = adm.Id,
                        Email = adm.Email,
                        Perfil = adm.Perfil
                    };

                return Results.Ok(administrador);
            }).WithTags("Administradores").RequireAuthorization(new AuthorizeAttribute{ Roles = "Adm" });

            #endregion

            #region Veiculos
            ErrosDeValidacao validaDTO(VeiculoDTO veiculoDTO){
                var validacao = new ErrosDeValidacao{
                    Mensagens = new List<string>()
                };

                if(string.IsNullOrEmpty(veiculoDTO.Nome))
                    validacao.Mensagens.Add("O nome não pode ser vazio");
                
                if (string.IsNullOrEmpty(veiculoDTO.Marca))
                    validacao.Mensagens.Add("A marca não pode ficar em branco");

                if (veiculoDTO.Ano < 1950)
                    validacao.Mensagens.Add("Veículo muito antigo, aceito apenas anos acima de 1950");
                
                return validacao;
            }

            endpoints.MapPost("/veiculos", ([FromBody] VeiculoDTO veiculoDTO, IVeiculoServico veiculoServico) => {
                var validacao = validaDTO(veiculoDTO);
                if(validacao.Mensagens.Count() > 0){
                    return Results.BadRequest(validacao);
                }

                var veiculo = new Veiculo {
                    Nome = veiculoDTO.Nome,
                    Marca = veiculoDTO.Marca,
                    Ano = veiculoDTO.Ano
                };
                veiculoServico.Incluir(veiculo);

                return Results.Created($"/veiculo/{veiculo.Id}", veiculo);
            })
            .WithTags("Veiculos")
            .RequireAuthorization(new AuthorizeAttribute{ Roles = "Adm, Editor" });

            endpoints.MapGet("/veiculos", ([FromQuery]int? pagina, IVeiculoServico veiculoServico) => {
                var veiculos = veiculoServico.Todos(pagina);

                return Results.Ok(veiculos);
            })
            .WithTags("Veiculos")
            .RequireAuthorization(new AuthorizeAttribute{ Roles = "Adm, Editor" });


            endpoints.MapGet("/veiculos/{id}", ([FromRoute]int id, IVeiculoServico veiculoServico) => {
                var veiculo = veiculoServico.BuscaPorId(id);

                if (veiculo == null) return Results.NotFound();

                return Results.Ok(veiculo);
            }).WithTags("Veiculos").RequireAuthorization();

            endpoints.MapPut("/veiculos/{id}", ([FromRoute]int id, VeiculoDTO veiculoDTO, IVeiculoServico veiculoServico) => {
                var veiculo = veiculoServico.BuscaPorId(id);
                if (veiculo == null) return Results.NotFound();
                
                var validacao = validaDTO(veiculoDTO);
                if(validacao.Mensagens.Count() > 0){
                    return Results.BadRequest(validacao);
                }
                
                veiculo.Nome = veiculoDTO.Nome;
                veiculo.Marca = veiculoDTO.Marca;
                veiculo.Ano = veiculoDTO.Ano;

                veiculoServico.Atualizar(veiculo);
                return Results.Ok(veiculo);
            })
            .WithTags("Veiculos")
            .RequireAuthorization(new AuthorizeAttribute{ Roles = "Adm" });


            endpoints.MapDelete("/veiculos/{id}", ([FromRoute]int id, IVeiculoServico veiculoServico) => {
                var veiculo = veiculoServico.BuscaPorId(id);
                if (veiculo == null) return Results.NotFound();

                veiculoServico.Apagar(veiculo);
                return Results.NoContent();
            })
            .WithTags("Veiculos")
            .RequireAuthorization(new AuthorizeAttribute{ Roles = "Adm" });


            #endregion
        });
    }
}