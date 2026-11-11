package chapter1;

// Импортируем исключение, которое выбрасывается, если алгоритм вообще не найден (стр. 5)
import java.security.NoSuchAlgorithmException;
// Импортируем класс Cipher для шифрования (стр. 2, 5)
import javax.crypto.Cipher;
// Импортируем SecretKeySpec для создания ключа из массива байтов (стр. 5)
import javax.crypto.spec.SecretKeySpec;

public class PolicyFileCheck
{
    public static void main(String[] args)
        throws NoSuchAlgorithmException
    {
        try
        {
            // Создаем объект шифра для алгоритма Blowfish в режиме ECB без паддинга
            // из провайдера Bouncy Castle ("BC"), как в листинге на стр. 5.
            Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC");

            // Пытаемся инициализировать шифр в режиме шифрования (ENCRYPT_MODE)
            // с ключом из 32 байтов (32 * 8 = 256 бит).
            // Если в JVM стоят старые экспортные ограничения (limited policy),
            // то ключ в 256 бит вызовет исключение InvalidKeyException / SecurityException.
            cipher.init(Cipher.ENCRYPT_MODE,
                     new SecretKeySpec(new byte[32], "Blowfish"));

            // Если инициализация прошла без ошибок — ограничения сняты (unlimited policy), выводим true.
            System.out.print("true");
        }
        catch (NoSuchAlgorithmException e)
        {
            // Если сам алгоритм Blowfish не найден, пробрасываем ошибку дальше (стр. 5).
            throw e;
        }
        catch (Exception e)
        {
            // Если возникла любая другая ошибка (например, из-за ограничения длины ключа в 256 бит),
            // значит в JVM действуют ограничения политики юрисдикции — выводим false.
            System.out.print("false");
        }
    }
}
