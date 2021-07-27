# .NET CORE - MVCCoreQueryEncrypt
Encrypt / decrypt query string parameters for ASP.NET MVC applications

5 Steps to use :

1. Download MVCCoreQueryEncrypt project

2. Add the project to your solution and reference the project accordingly, Modify

<p>&lt;a href='@Url.Action(&quot;TestEncrypt&quot;, new {id=7, a = 1, b = &quot;asd&quot; })'&gt;Test&lt;/a&gt;</p>

into 

<p>&lt;a href='@Url.Encrypt(&quot;TestEncrypt&quot;, new {id=7, a = 1, b = &quot;asd&quot; })'&gt;Test&lt;/a&gt;</p>
( Add as first line in the view:

@using MVCCoreQueryEncrypt;
)

3. Setup the Salt & Secret in the Startup.cs

//Retrieve the salt and secret from a secure location
 <p>services.MvcCoreQueryEncryptionServices(/*salt value */, /*secret value*/);</p>

4. Add the action filter DecryptFilter to action methods that need to decrypt parameters

[DecryptFilter] 

5. Check out the demo application
