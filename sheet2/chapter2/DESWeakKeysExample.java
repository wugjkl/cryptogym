package chapter2;

import java.security.GeneralSecurityException;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

/**
 * Demonstrates the involution property {@code E_K(E_K(P)) == P} of the four classic DES weak keys
 * by modifying {@code ECBShortExample} (Hook &amp; Eaves, 2025, p. 24) to use {@code DES/ECB/NoPadding}
 * (Exercise 2.2).
 *
 * @author Daniel
 */
public class DESWeakKeysExample
{
    /**
     * Executes double encryption in {@link Cipher#ENCRYPT_MODE} for each of the four 64-bit DES weak keys
     * to verify that encrypting the ciphertext a second time reproduces the original plaintext.
     *
     * @param args command-line arguments (unused)
     * @throws GeneralSecurityException if the DES cipher or key initialization fails
     */
    public static void main(String[] args)
        throws GeneralSecurityException
    {
        // Регистрируем провайдер Bouncy Castle, как в примерах Главы 1 (стр. 3)
        Security.addProvider(new BouncyCastleProvider());

        // Записываем в массив все 4 известных слабых ключа алгоритма DES (каждый по 8 байтов = 16 hex-символов)
        String[] weakKeysHex = new String[] {
            "0101010101010101",
            "fefefefefefefefe",
            "1f1f1f1f0e0e0e0e",
            "e0e0e0e0f1f1f1f1"
        };

        // Берем входной открытый текст из ECBShortExample (стр. 24): 16 байтов (ровно 2 блока DES по 8 байтов)
        byte[] input = Hex.decode("a0a1a2a3a4a5a6a7a0a1a2a3a4a5a6a7");

        // Создаем объект Cipher для алгоритма DES в режиме ECB без паддинга (вместо AES со стр. 24)
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding", "BC");

        // Проходим циклом по всем 4 слабым ключам (оформляем цикл как в ListProviders на стр. 6)
        for (int i = 0; i != weakKeysHex.length; i++)
        {
            // Переводим текущую hex-строку слабого ключа в массив из 8 байтов (стр. 24, строка 12)
            byte[] keyBytes = Hex.decode(weakKeysHex[i]);

            // Создаем ключ SecretKeySpec для алгоритма "DES" (стр. 24, строка 14)
            SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");

            System.out.println("=== Weak Key " + (i + 1) + ": " + weakKeysHex[i] + " ===");
            System.out.println("input            : " + Hex.toHexString(input));

            // Инициализируем шифр в режиме ШИФРОВАНИЯ (ENCRYPT_MODE) со слабым ключом (стр. 24, строка 22)
            cipher.init(Cipher.ENCRYPT_MODE, key);

            // Первый раз шифруем открытый текст input и получаем шифротекст output (стр. 24, строка 24)
            byte[] output = cipher.doFinal(input);
            System.out.println("encrypted (1st)  : " + Hex.toHexString(output));

            // ДЕМОНСТРАЦИЯ СВОЙСТВА СЛАБОГО КЛЮЧА:
            // Оставляем шифр в режиме ENCRYPT_MODE и повторно шифруем output тем же слабым ключом:
            byte[] encryptedTwice = cipher.doFinal(output);
            System.out.println("encrypted (2nd)  : " + Hex.toHexString(encryptedTwice));

            // Проверяем обычный режим расшифрования (DECRYPT_MODE), как на стр. 24:
            cipher.init(Cipher.DECRYPT_MODE, key);
            System.out.println("decrypted normal : " + Hex.toHexString(cipher.doFinal(output)));
            System.out.println();
        }
    }
}
