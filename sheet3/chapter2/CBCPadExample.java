package chapter2;

// Импортируем Arrays для обрезки выходного буфера до реальной длины методом copyOfRange (стр. 30–31)
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Hex;

public class CBCPadExample
{
    public static void main(String[] args)
        throws Exception
    {
        // Создаем 16-байтовый ключ для AES (стр. 30, строка 14)
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        // Создаем шифр AES в режиме CBC с дополнением PKCS5Padding (в JCA оно же реализует PKCS#7, стр. 29–30)
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");

        // Создаем массив открытого текста длиной 24 байта (не кратно размеру блока AES в 16 байтов!),
        // чтобы проверить, как работает автоматическое добавление и снятие паддинга (стр. 30, строки 20–21).
        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7"
                                + "a0a1a2a3a4a5a6a7");

        System.out.println("input : " + Hex.toHexString(input));

        // Инициализируем шифр на шифрование; он сам создаст случайный IV (стр. 30, строка 25)
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Сохраняем сгенерированный IV через getIV() для последующего расшифрования (стр. 30, строка 27)
        byte[] iv = cipher.getIV();

        // Шифруем 24 байта открытого текста. Из-за паддинга PKCS5/PKCS7 к ним добавится 8 байтов со значением 0x08,
        // поэтому размер массива output станет равен 32 байтам (2 полных блока AES) (стр. 31, строка 28).
        byte[] output = cipher.doFinal(input);

        System.out.println("encrypted: " + Hex.toHexString(output));

        // Инициализируем шифр на расшифрование с ключом key и сохраненным вектором iv (стр. 31, строка 30)
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        // Выделяем выходной буфер finalOutput. Метод cipher.getOutputSize(output.length) возвращает
        // МАКСИМАЛЬНО возможный размер результата (32 байта), так как до расшифрования последнего блока
        // шифр еще не знает, сколько именно байтов паддинга будет в конце! (стр. 31, строка 31).
        byte[] finalOutput = new byte[cipher.getOutputSize(output.length)];

        // Передаем данные в шифр через update(). Он расшифровывает первые блоки, а последний блок
        // придерживает во внутреннем буфере до вызова doFinal, чтобы проверить и отрезать паддинг.
        // Переменная len хранит количество байтов, реально записанных в finalOutput на этом шаге (стр. 31, строка 33).
        int len = cipher.update(output, 0, output.length, finalOutput, 0);

        // Вызываем doFinal(finalOutput, len), который дописывает оставшиеся байты (после удаления паддинга)
        // в массив finalOutput начиная с индекса len, и прибавляем их количество к общей длине len (стр. 31, строка 35).
        // В итоге len становится равна 24 (реальная длина открытого текста), хотя размер finalOutput был 32!
        len += cipher.doFinal(finalOutput, len);

        // Отрезаем лишние нулевые байты в хвосте буфера finalOutput с помощью Arrays.copyOfRange(finalOutput, 0, len),
        // оставляя только реально расшифрованные len (24) байтов (стр. 31, строка 37).
        System.out.println("decrypted: "
             + Hex.toHexString(Arrays.copyOfRange(finalOutput, 0, len)));
    }
}
