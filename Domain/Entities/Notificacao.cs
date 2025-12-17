namespace auth.Domain.Entities;

public class Notificacao
{
    public string Mensagem { get; }
    public Notificacao(string mensagem)
    {
        Mensagem = mensagem;
    }
}
