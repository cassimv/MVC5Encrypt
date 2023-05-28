using System.Linq;
using System.Threading.Tasks;
using System;
using System.Web;
using Microsoft.AspNetCore.Mvc.Filters;
using MVCCoreQueryEncrypt.ServiceConfiguration;

namespace MVCCoreQueryEncrypt
{
    /// <summary>
    /// MVC attribute to decrypt parameters- make sure that secret is the same as in
    /// <see>
    ///     <cref>UrLExtensions.ActionEnc(UrlHelper, string, string, object)</cref>
    /// </see>
    /// or    
    /// </summary>
    public class DecryptFilterAttribute : Attribute, IAsyncResourceFilter
    {
        /// <summary>
        /// the encrypt decrypt full class name
        /// must inherit from <see cref="IEncryptDecrypt"/>
        /// </summary>
        public string EncDecFullClassName;

        /// <summary>
        /// executes and decrypts
        /// </summary>
        public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
        {
            IEncryptDecrypt encDec;
            if (string.IsNullOrWhiteSpace(EncDecFullClassName))
            {
                encDec = new EncryptDecrypt(ServicesExtensions.MvcDecryptFilterSecret);
            }
            else
            {
                var encryptionType = Type.GetType(EncDecFullClassName);

                if (encryptionType == null)
                {
                    throw new ArgumentException(" Cannot determine type of encryption class");
                }

                encDec = Activator.CreateInstance(encryptionType) as IEncryptDecrypt;

                if (encDec == null)
                {
                    throw new ArgumentException(" Cannot convert " + EncDecFullClassName + " to IEncryptDecrypt");
                }
            }

            var args = HttpUtility.ParseQueryString(context.HttpContext.Request.QueryString.ToString());
            var parametersAction = context.ActionDescriptor.Parameters;
            for (var i = 0; i < args.Count; i++)
            {
                var value = args[i]?.Replace(' ', '+');
                var name = args.GetKey(i);
                var type = parametersAction.First(it => it.Name == name).ParameterType;
                context.RouteData.Values[name ?? string.Empty] = ChangeType(encDec.DecryptString(value), type);
            }

            await next();
        }

        private static object ChangeType(object value, Type conversion)
        {
            var parType = conversion;

            if (!parType.IsGenericType || parType.GetGenericTypeDefinition() != typeof(Nullable<>))
                return Convert.ChangeType(value, parType);
            if (value == null) return null;
            parType = Nullable.GetUnderlyingType(parType);
            return parType == null ? null : Convert.ChangeType(value, parType);
        }
    }
}
