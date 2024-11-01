using minimal_api.Dominio.Enums;

namespace minimal_api.Dominio.ModelViews;
record AdministradorLogado
{
    public string Email { get;set; } = default!;
    public string Perfil { get;set; } = default!;
    public string Token { get;set; } = default!;
}