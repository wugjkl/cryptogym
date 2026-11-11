package chapter1;

// Импортируем Iterator для обхода ключей внутри объекта Provider (стр. 7)
import java.util.Iterator;
// Импортируем Provider и Security (стр. 7)
import java.security.Provider;
import java.security.Security;

public class ListProviderCapabilities
{
    public static void main(String[] args)
    {
        // Проверяем, что пользователь передал ровно один аргумент командной строки (имя провайдера).
        if (args.length != 1)
        {
            // Если аргумент не передан, выводим подсказку по запуску в поток ошибок (стр. 7)
            System.err.println(
                 "usage: chapter1.ListProviderCapabilites provider_name");
            // Завершаем программу с кодом ошибки 1
            System.exit(1);
        }

        // Ищем установленный провайдер по имени, переданному в первом аргументе args[0] (стр. 7).
        Provider provider = Security.getProvider(args[0]);

        // Проверяем, нашелся ли такой провайдер в JVM
        if (provider != null)
        {
            // Класс Provider наследуется от Properties, поэтому мы можем взять набор его ключей keySet()
            // и пройтись по нему через обычный Iterator (стр. 7, строки 21–22).
            for (Iterator it = provider.keySet().iterator(); it.hasNext();)
            {
                // Берем очередную запись (ключ свойства) и приводим к типу String
                String entry = (String)it.next();
                // Флаг, показывающий, является ли текущая запись псевдонимом (алиасом) другого алгоритма
                boolean isAlias = false;

                // Если строка начинается с "Alg.Alias", значит это псевдоним алгоритма (стр. 7, строка 27).
                if (entry.startsWith("Alg.Alias"))
                {
                    // Помечаем, что это алиас
                    isAlias = true;
                    // Отрезаем префикс "Alg.Alias." (длина "Alg.Alias" + 1 символ на точку),
                    // чтобы осталась строка вида "ТипСервиса.ИмяАлгоритма" (стр. 7, строка 30).
                    entry = entry.substring("Alg.Alias".length() + 1);
                }

                // Вырезаем тип сервиса (например, "Cipher" или "MessageDigest") — всё до первой точки (стр. 7, строка 33).
                String serviceName = entry.substring(
                                               0, entry.indexOf('.'));
                // Вырезаем само имя алгоритма — всё, что идет после точки (стр. 7, строка 35).
                String name = entry.substring(serviceName.length() + 1);

                // Если это был алиас, выводим также то реальное имя алгоритма, на которое он указывает
                if (isAlias)
                {
                    System.out.print(serviceName + ": " + name);
                    // Через provider.get("Alg.Alias." + entry) достаем базовое имя алгоритма (стр. 7–8)
                    System.out.println(" (alias for "
                             + provider.get("Alg.Alias." + entry) + ")");
                }
                else
                {
                    // Если это основной алгоритм, а не алиас — просто выводим тип сервиса и имя (стр. 8)
                    System.out.println(serviceName + ": " + name);
                }
            }
        }
        else
        {
            // Если провайдер с именем args[0] не найден, сообщаем об этом и выходим (стр. 8)
            System.err.println("provider " + args[0] + " not found");
            System.exit(1);
        }
    }
}
