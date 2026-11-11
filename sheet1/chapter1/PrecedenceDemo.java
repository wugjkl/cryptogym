package chapter1;

// Импортируем класс MessageDigest для работы с хеш-функциями (стр. 2–3)
import java.security.MessageDigest;
// Импортируем класс Security для управления криптопровайдерами в JVM (стр. 3)
import java.security.Security;
// Импортируем провайдер Bouncy Castle (стр. 3)
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PrecedenceDemo
{
    public static void main(String[] args)
        throws Exception
    {
        // Регистрируем провайдер Bouncy Castle динамически во время работы программы.
        // Метод addProvider() добавляет его в самый КОНЕЦ списка приоритетов (стр. 3).
        Security.addProvider(new BouncyCastleProvider());

        // Запрашиваем алгоритм SHA1 БЕЗ указания конкретного провайдера.
        // JCA просматривает список установленных провайдеров по порядку с начала списка
        // и берет первый попавшийся провайдер, где есть SHA1 (обычно это стандартный SUN).
        System.out.println(MessageDigest.getInstance("SHA1")
                                 .getProvider().getName());

        // Запрашиваем алгоритм SHA1 и явно указываем вторым аргументом имя провайдера "BC".
        // Теперь JCA обязана взять реализацию именно из провайдера Bouncy Castle (стр. 3).
        System.out.println(MessageDigest.getInstance("SHA1", "BC")
                                 .getProvider().getName());
    }
}
