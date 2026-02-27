using Auth.Domain.Entities;

namespace Auth.Infra.Notifications;

public interface INotificador
{
    bool TemNotificacao();
    List<Notificacao> ObterNotificacoes();
    void Handle(Notificacao notificacao);
}
