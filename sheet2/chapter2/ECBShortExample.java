package chapter2;

// Импортируем класс Cipher для выполнения шифрования и расшифрования (стр. 21, 24)
import javax.crypto.Cipher;
// Импортируем SecretKeySpec для создания ключа из готового массива байтов (стр. 22, 24)
import javax.crypto.spec.SecretKeySpec;
// Импортируем утилиту Hex из Bouncy Castle для перевода hex-строк в байты и обратно (стр. 24)
import org.bouncycastle.util.encoders.Hex;

public class ECBShortExample
{
    public static void main(String[] args)
        throws Exception
    {
        // Переводим шестнадцатеричную строку (32 hex-символа = 16 байтов = 128 бит)
        // в массив байтов для ключа AES с помощью метода Hex.decode() (стр. 24, строка 12).
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");

        // Оборачиваем массив байтов keyBytes в объект ключа SecretKeySpec,
        // указывая, что этот ключ предназначен для алгоритма "AES" (стр. 22, 24).
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        // Получаем экземпляр шифра для алгоритма AES в режиме ECB без паддинга (NoPadding)
        // из провайдера Bouncy Castle ("BC") (стр. 24, строка 16).
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");

        // Создаем массив входных данных (открытый текст) длиной 16 байтов (1 блок AES).
        // Обратите внимание: первые 8 байтов (a0..a7) и вторые 8 байтов одинаковы (стр. 24).
        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");

        // Выводим исходный открытый текст в шестнадцатеричном виде на экран
        System.out.println("input : " + Hex.toHexString(input));

        // Переводим шифр в режим шифрования (Cipher.ENCRYPT_MODE) с нашим ключом key (стр. 24, строка 22).
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Шифруем весь блок входных данных за один вызов метода doFinal()
        // и сохраняем полученный шифротекст в массив output (стр. 21, 24).
        byte[] output = cipher.doFinal(input);

        // Выводим зашифрованный блок в виде hex-строки
        System.out.println("encrypted: " + Hex.toHexString(output));

        // Переводим тот же самый объект шифра в режим расшифрования (Cipher.DECRYPT_MODE)
        // с тем же самым секретным ключом key (стр. 24, строка 28).
        cipher.init(Cipher.DECRYPT_MODE, key);

        // Расшифровываем массив output через doFinal() и сразу выводим результат в hex-виде.
        // Он полностью совпадает с исходным массивом input (стр. 24, строки 30–31).
        System.out.println("decrypted: "
                  + Hex.toHexString(cipher.doFinal(output)));
    }
}
