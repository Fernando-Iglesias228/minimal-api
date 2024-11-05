namespace MinimalApi.Dominio.ModelViews;
record AdministradorMV
{
    public int Id { get;set; } = default!;
    public string Email { get;set; } = default!;
    public string Perfil { get;set; } = default!;
}