package chapter1;

// Импортируем класс Provider, представляющий отдельный криптопровайдер (стр. 6)
import java.security.Provider;
// Импортируем класс Security для получения массива всех провайдеров (стр. 6)
import java.security.Security;

public class ListProviders
{
    public static void main(String[] args)
    {
        // Получаем массив всех провайдеров, которые сейчас установлены в системе (стр. 6).
        Provider[] installedProvs = Security.getProviders();

        // Проходим обычным циклом for по всем элементам массива installedProvs,
        // точно как у авторов книги на стр. 6 (условие i != installedProvs.length).
        for (int i = 0; i != installedProvs.length; i++)
        {
            // Выводим краткое имя текущего провайдера (например, "SUN" или "BC")
            System.out.print(installedProvs[i].getName());
            // Выводим двоеточие с пробелом для разделения имени и описания
            System.out.print(": ");
            // Выводим текстовое описание провайдера через метод getInfo()
            System.out.print(installedProvs[i].getInfo());
            // Переводим строку перед выводом следующего провайдера
            System.out.println();
        }
    }
}
