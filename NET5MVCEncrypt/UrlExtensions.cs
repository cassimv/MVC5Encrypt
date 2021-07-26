using System;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using MVCCoreQueryEncrypt.ServiceConfiguration;

namespace MVCCoreQueryEncrypt
{
    /// <summary>
    /// extension for having syntax like
    /// <a href='@Url.ActionEnc("mySecret", "TestEncrypt", new { a = 1, b = "asd" })'>Test</a>
    /// </summary>
    public static class UrlHelperExtension
    {
        /// <summary>
        /// default implementation 
        /// </summary>
        /// <param name="helper"></param>
        /// <param name="actionName"></param>
        /// <param name="routeValues"></param>
        /// <returns></returns>
        public static string Encrypt(this IUrlHelper helper, string actionName, object routeValues)
        {
            return GenerateEncryptedLink(helper.Action(actionName, routeValues), 
                new EncryptDecrypt(ServicesExtensions.MvcDecryptFilterSecret));
        }
        /// <summary>
        /// generic implementation 
        /// </summary>
        /// <param name="helper"></param>
        /// <param name="actionName"></param>
        /// <param name="controllerName"></param>
        /// <param name="routeValues"></param>
        /// <returns></returns>
        public static string Encrypt(this IUrlHelper helper, string actionName, string controllerName, object routeValues)
        {
            return GenerateEncryptedLink(helper.Action(actionName, controllerName, routeValues), 
                new EncryptDecrypt(ServicesExtensions.MvcDecryptFilterSecret));
        }
        private static string GenerateEncryptedLink(string url, IEncryptDecrypt encDec)
        {
            var index = url.IndexOf("?", StringComparison.Ordinal);
            if (index == -1)
                return url;

            var uri = new Uri(url, UriKind.RelativeOrAbsolute);
            var absoluteUri = uri.IsAbsoluteUri ? uri : new Uri(new Uri("http://www.google.com"), uri);

            var args = HttpUtility.ParseQueryString(absoluteUri.Query);
            if (args.Count == 0)
            {
                return url;
            }

            for (var i = 0; i < args.Count; i++)
            {
                var key = args.GetKey(i);
                args[key] = encDec.EncryptString(args[i]);
            }

            return url[..(index + 1)] + args;
        }
    }
}
