using Microsoft.Extensions.DependencyInjection;

namespace MVCCoreQueryEncrypt.ServiceConfiguration
{
    public static class ServicesExtensions
    {
        public static string MvcEncryptSalt { get; set; }
        public static string MvcDecryptFilterSecret { get; set; }

        public static void MvcCoreQueryEncryptionService(this IServiceCollection services, string salt, string secret)
        {
            MvcDecryptFilterSecret = secret;
            MvcEncryptSalt = salt;
        }
    }
}
