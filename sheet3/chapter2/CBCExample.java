package chapter2;

// Импортируем Cipher для работы с блочным шифром (стр. 26)
import javax.crypto.Cipher;
// Импортируем IvParameterSpec для передачи вектора инициализации (IV) в шифр (стр. 26)
import javax.crypto.spec.IvParameterSpec;
// Импортируем SecretKeySpec для создания секретного ключа (стр. 26)
import javax.crypto.spec.SecretKeySpec;
// Импортируем утилиту Hex для декодирования и вывода hex-строк (стр. 26)
import org.bouncycastle.util.encoders.Hex;

public class CBCExample
{
    public static void main(String[] args)
        throws Exception
    {
        // Создаем массив из 16 байтов (128 бит) для ключа AES из hex-строки (стр. 26, строка 13)
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");

        // Оборачиваем байты в объект ключа SecretKeySpec для алгоритма "AES" (стр. 26, строка 15)
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        // Создаем экземпляр шифра AES в режиме CBC без паддинга (стр. 26, строка 17)
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");

        // Берем открытый текст из 2 одинаковых блоков по 16 байтов (всего 32 байта),
        // чтобы увидеть, что в режиме CBC одинаковые блоки открытого текста дают РАЗНЫЙ шифротекст (стр. 26).
        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7"
                                + "a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");

        // Выводим исходный открытый текст на экран
        System.out.println("input : " + Hex.toHexString(input));

        // Задаем массив из 16 байтов для вектора инициализации (IV) — размер IV равен размеру блока AES (стр. 26)
        byte[] iv = Hex.decode("0102030405060708090a0b0c0d0e0f10");

        // Инициализируем шифр на шифрование (ENCRYPT_MODE), передавая ключ key
        // и вектор инициализации, обернутый в объект IvParameterSpec(iv) (стр. 27, строка 26).
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        // Шифруем оба блока открытого текста вызовом doFinal(input) (стр. 27, строка 28)
        byte[] output = cipher.doFinal(input);

        // Выводим зашифрованный результат: оба 16-байтовых блока теперь совершенно разные!
        System.out.println("encrypted: " + Hex.toHexString(output));

        // Инициализируем шифр на расшифрование (DECRYPT_MODE) с тем же ключом и ТЕМ ЖЕ САМЫМ вектором iv (стр. 27, строка 32)
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        // Расшифровываем шифротекст output и выводим восстановленный открытый текст (стр. 27, строки 34–35)
        System.out.println("decrypted: "
                  + Hex.toHexString(cipher.doFinal(output)));
    }
}
