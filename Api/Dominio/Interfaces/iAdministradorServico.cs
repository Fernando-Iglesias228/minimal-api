using MinimalApi.Dominio.Entidades;
using MinimalApi.Dominio.DTOs;

namespace MinimalApi.Dominio.Interfaces;
public interface IAdministradorServico{
    public Administrador? Login(LoginDTO loginDTO);
    public Administrador Incluir(Administrador administrador);
    public Administrador? BuscaPorId(int id);
    public List<Administrador> Todos(int? pagina);
}