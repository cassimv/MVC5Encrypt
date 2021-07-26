using System;
using System.Linq;
using System.Threading.Tasks;
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
        /// decrypts parameters in the ASP.NET CORE Pipeline
        /// </summary>
        public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
        {
            IEncryptDecrypt encDec = new EncryptDecrypt(ServicesExtensions.MvcDecryptFilterSecret);
            var args = HttpUtility.ParseQueryString(context.HttpContext.Request.QueryString.ToString() ?? string.Empty);
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
        /// <summary>
        /// Assigns decrypted value to parameter
        /// </summary>
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
