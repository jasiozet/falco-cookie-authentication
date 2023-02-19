open Falco
open Falco.Routing
open Falco.HostBuilder
open Microsoft.AspNetCore.Authentication
open System.Security.Claims
open Falco.Markup

[<Literal>]
let AuthnTypeName = "usr"

let secureResourceHandler : HttpHandler =
  let handleAuth : HttpHandler =
    fun ctx ->
      let name =
        ctx.User.Identities
        |> Seq.head
        |> fun x -> x.Claims
        |> Seq.filter (fun x -> x.Type = AuthnTypeName)
        |> Seq.head
        |> fun x -> x.Value
      Response.ofPlainText $"hello authenticated user: {name}" ctx

  let handleInvalid : HttpHandler =
    Response.withStatusCode 403
    >> Response.ofPlainText "Forbidden"

  Request.ifAuthenticated handleAuth handleInvalid

let signInHandler : HttpHandler =
  let claims = [Claim(AuthnTypeName, "authn_falconista")]
  let claimsIdentity = ClaimsIdentity(claims, Cookies.CookieAuthenticationDefaults.AuthenticationScheme)
  let claimsPrincipal = ClaimsPrincipal(claimsIdentity)
  Response.signInAndRedirect Cookies.CookieAuthenticationDefaults.AuthenticationScheme claimsPrincipal "/secure"

let signOutHandler : HttpHandler =
  Response.signOutAndRedirect Cookies.CookieAuthenticationDefaults.AuthenticationScheme "/secure"

let mainPageHandler : HttpHandler =
  let page = Elem.html [] [
    Elem.body [] [
      Elem.a [Attr.href "/signin"] [Text.raw "Sign in"]
      Elem.hr []
      Elem.a [Attr.href "/signout"] [Text.raw "Sign out"]
    ]
  ]
  Response.ofHtml page

[<EntryPoint>]
let main args =
  webHost args {
    add_cookie Cookies.CookieAuthenticationDefaults.AuthenticationScheme (fun cookieAuthOptions -> ())
    use_authentication
    endpoints [
        get "/"         mainPageHandler
        get "/secure"   secureResourceHandler
        get "/signin"   signInHandler
        get "/signout"  signOutHandler
    ]
  }
  0