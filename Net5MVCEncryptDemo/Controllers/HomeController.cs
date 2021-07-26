using Microsoft.AspNetCore.Mvc;
using MVCCoreQueryEncrypt;

namespace Net5MVCEncryptDemo.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
        [DecryptFilter]
        public ActionResult EncryptedAction(int id, int val1, string val2)
        {
            if (!ModelState.IsValid) return RedirectToAction("ModelInvalid");

            ViewBag.id = id;
            ViewBag.val1 = val1;
            ViewBag.val2 = val2;
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "An application to encrypt the query string parameters for .Net Core MVC Applications";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        public ActionResult ModelInvalid()
        {
            ViewBag.Message = "The Model Is Invalid.";

            return View();
        }
    }
}