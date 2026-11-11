package chapter2;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;

public class CTSExample
{
    public static void main(String[] args)
        throws Exception
    {
        // Декодируем 16-байтовый ключ для алгоритма AES (стр. 32, строка 13)
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        // Запрашиваем шифр AES в режиме CBC с механизмом кражи шифротекста "CTSPadding" (стр. 32, строка 17)
        Cipher cipher = Cipher.getInstance("AES/CBC/CTSPadding", "BC");

        // Берем открытый текст длиной 24 байта (1,5 блока AES: больше одного блока, но не кратно 16 байтам) (стр. 32, строки 19–20)
        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7"
                                + "a0a1a2a3a4a5a6a7");

        System.out.println("input : " + Hex.toHexString(input));

        // Инициализируем шифр на шифрование (IV создается автоматически) (стр. 32, строка 24)
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Сохраняем сгенерированный IV (стр. 32, строка 26)
        byte[] iv = cipher.getIV();

        // Шифруем 24 байта. Благодаря механизму CTS (Cipher Text Stealing) размер шифротекста output
        // составляет ровно 24 байта — ни одного лишнего байта к длине сообщения не прибавилось! (стр. 32, строка 28)
        byte[] output = cipher.doFinal(input);

        System.out.println("encrypted: " + Hex.toHexString(output));

        // Инициализируем шифр на расшифрование с ключом key и вектором iv (стр. 32, строка 32)
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        // Выделяем буфер под расшифрованный текст через getOutputSize (стр. 32, строка 34)
        byte[] finalOutput = new byte[cipher.getOutputSize(output.length)];

        // Выполняем потоковое обновление update() и финальный вызов doFinal() с подсчетом реальной длины len (стр. 33, строки 36–38)
        int len = cipher.update(output, 0, output.length, finalOutput, 0);

        len += cipher.doFinal(finalOutput, len);

        // Выводим ровно len расшифрованных байтов через Arrays.copyOfRange (стр. 33, строка 40)
        System.out.println("decrypted: "
            + Hex.toHexString(Arrays.copyOfRange(finalOutput, 0, len)));
    }
}
