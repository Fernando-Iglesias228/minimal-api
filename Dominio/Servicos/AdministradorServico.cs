using System.Data.Common;
using Microsoft.AspNetCore.Http.HttpResults;
using MinimalApi.Dominio.Entidades;
using MinimalApi.Dominio.Interfaces;
using MinimalApi.DTOs;
using MinimalApi.Infraestrutura.Db;

namespace MinimalApi.Dominio.Servicos;

public class AdministradorServico : IAdministradorServico
{
    private readonly DbContexto _contexto;
    public AdministradorServico(DbContexto contexto)
    {
        _contexto = contexto;
    }
    public Administrador? Login(LoginDTO loginDTO){
        var adm = _contexto.Administradores.Where(a => a.Email == loginDTO.Email && a.Senha == loginDTO.Senha).FirstOrDefault();
        return adm;
    }

    Administrador? IAdministradorServico.BuscaPorId(int id)
    {
        var administrador = _contexto.Administradores.Find(id);
        return administrador;
    }

    Administrador IAdministradorServico.Incluir(Administrador administrador)
    {
        _contexto.Administradores.Add(administrador);
        _contexto.SaveChanges();

        return administrador;
    }

    List<Administrador> IAdministradorServico.Todos(int? pagina)
    {
        var query = _contexto.Administradores.AsQueryable();
    
        int itensPorPagina = 10;

        if(pagina != null){
            query = query.Skip(((int)pagina - 1) * itensPorPagina).Take(itensPorPagina);
        }
        return query.ToList();
    }
}