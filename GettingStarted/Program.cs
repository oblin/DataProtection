using System;
using System.IO;
using System.Threading;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

namespace ConsoleApplication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var serviceColletion = new ServiceCollection();
            serviceColletion.AddDataProtection();
            var services = serviceColletion.BuildServiceProvider();

            var instance = ActivatorUtilities.CreateInstance<MyClass>(services);
            instance.RunSample();

            ProtectorForLimitedTime();
        }

        private static void ProtectorForLimitedTime()
        {
            var provider = DataProtectionProvider.Create(Directory.GetCurrentDirectory());
            var baseProtector = provider.CreateProtector("MySettings.TimeLimitedSample");
            var timeLimitedProtector = baseProtector.ToTimeLimitedDataProtector();

            Console.Write("Enter input: ");
            string input = Console.ReadLine();
            string protectedData = timeLimitedProtector.Protect(input, lifetime: TimeSpan.FromSeconds(5));

            // Unprotect 
            string roundTripped = timeLimitedProtector.Unprotect(protectedData);
            Console.WriteLine($"Round-tripped data: {roundTripped}");

            // Wait for 6 seconds, and show Cryptography.CryptographicException
            Console.WriteLine("Waiting 6 seconds...");
            Thread.Sleep(6000);
            timeLimitedProtector.Unprotect(protectedData);
        }
    }

    public class MyClass
    {
        private IDataProtector _protector;

        public MyClass(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector("MySettings.MyClass.v1");
        }

        public void RunSample()
        {
            Console.Write("Enter input: ");
            string input = Console.ReadLine();

            string protectedPayload = _protector.Protect(input);
            Console.WriteLine($"Protect returned: {protectedPayload}");

            string unprotectedPayload = _protector.Unprotect(protectedPayload);
            Console.WriteLine($"UnProtect returned: {unprotectedPayload}");
        }
    }
}
