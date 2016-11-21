using System;
using System.IO;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using static System.Console;

namespace ConsoleApplication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var destDir = Path.Combine(
                Environment.GetEnvironmentVariable("LOCALAPPDATA"),
                "AppSecrets"); 
            var serviceColletion = new ServiceCollection();
            serviceColletion.AddDataProtection()
                // 設定儲存的位置
                .PersistKeysToFileSystem(new DirectoryInfo(destDir));
            var services = serviceColletion.BuildServiceProvider();
            // 取得 protector
            var protector = services.GetDataProtector("Persist.Protector.Sample");

            Write("Input: ");
            // 測試使用 byte[] （也可以使用 string）
            byte[] input = Encoding.UTF8.GetBytes(ReadLine());
            var protectedData = protector.Protect(input);
            WriteLine($"Protected payload: {Convert.ToBase64String(protectedData)}");
            var roundTripped = protector.Unprotect(protectedData);
            WriteLine($"Round-tripped payload: {Encoding.UTF8.GetString(roundTripped)}");

            // 取出 key manager 用來 revoke key
            var keyManager = services.GetService<IKeyManager>();
            WriteLine("Revoking all keys in the key rings...");
            keyManager.RevokeAllKeys(DateTimeOffset.Now, "For Testing.");

            WriteLine("Calling unprotect");
            try {
                var unprotectPayload = protector.Unprotect(protectedData);
                WriteLine($"un-protected payload: {Encoding.UTF8.GetString(unprotectPayload)}");
            } catch (Exception e) {
                WriteLine($"{e.GetType().Name}: {e.Message}");
            }

            Console.WriteLine("Calling DangerousUnprotect...");
            try {
                IPersistedDataProtector persistedProtector = protector as IPersistedDataProtector;
                if (persistedProtector == null)
                    throw new Exception("無法呼叫 DangerousUnprotect");

                bool requiredMigration, wasRevoked;
                var unprotectPayload = persistedProtector.DangerousUnprotect(
                    protectedData: protectedData,
                    ignoreRevocationErrors: true,
                    requiresMigration: out requiredMigration,
                    wasRevoked: out wasRevoked
                );

                WriteLine($"Unprotected payload: {Encoding.UTF8.GetString(unprotectPayload)}");
                WriteLine($"Requires migration = {requiredMigration}, was Revoked = {wasRevoked}");
            } catch (Exception e) {
                WriteLine($"{e.GetType().Name}: {e.Message}");
            }
        }
    }
}
