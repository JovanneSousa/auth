using auth.Src.Domain.Entities;

namespace auth.Src.Domain.Interfaces;

public interface INotificador
{
    bool TemNotificacao();
    List<Notificacao> ObterNotificacoes();
    void Handle(Notificacao notificacao);
}
