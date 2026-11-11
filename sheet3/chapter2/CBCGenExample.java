package chapter2;

// Импортируем Cipher, IvParameterSpec, SecretKeySpec и Hex (стр. 28)
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;

public class CBCGenExample
{
    public static void main(String[] args)
        throws Exception
    {
        // Декодируем 16-байтовый ключ AES из hex-строки (стр. 28, строка 13)
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");

        // Создаем SecretKeySpec для алгоритма "AES" (стр. 28, строка 15)
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        // Получаем шифр "AES/CBC/NoPadding" из провайдера Bouncy Castle (стр. 28, строка 17)
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");

        // Подготавливаем 32 байта (2 блока AES) открытого текста (стр. 28, строки 19–20)
        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7"
                                + "a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");

        System.out.println("input : " + Hex.toHexString(input));

        // Инициализируем шифр в режиме ENCRYPT_MODE БЕЗ передачи третьего параметра (без IV)!
        // Так как режим CBC требует IV, объект Cipher сам автоматически генерирует случайный IV (стр. 28, строка 24).
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Забираем автоматически сгенерированный вектор инициализации через метод cipher.getIV() (стр. 28, строка 26),
        // чтобы потом мы смогли передать его при расшифровании.
        byte[] iv = cipher.getIV();

        // Шифруем входной массив input (стр. 28, строка 28)
        byte[] output = cipher.doFinal(input);

        // Выводим сгенерированный шифром случайный IV и сам шифротекст (стр. 28, строки 30–31)
        System.out.println("iv : " + Hex.toHexString(iv));
        System.out.println("encrypted: " + Hex.toHexString(output));

        // При расшифровании (DECRYPT_MODE) обязательно передаем сохраненный массив iv через IvParameterSpec(iv) (стр. 28, строка 33)
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        // Расшифровываем и выводим исходный текст (стр. 28, строки 35–36)
        System.out.println("decrypted: "
                  + Hex.toHexString(cipher.doFinal(output)));
    }
}
