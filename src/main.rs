use actix_web::{server, HttpResponse, Responder, HttpRequest, App, Result, Form};
use actix_web::http::{StatusCode, Method, header};
use actix_web::middleware::session::{CookieSessionBackend, SessionStorage};
use base64;
use std::env;


#[derive(Deserialize)]
struct LoginForm {
    user: String, //email or phone
}

fn home(request: HttpRequest) -> impl Responder {
    HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body("Welcome Home!".to_string())
}

fn login_page(_: HttpRequest) -> Result<HttpResponse> {
    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/login.html")))
}

fn login_submit((form, request): (Form<LoginForm>, HttpRequest)) -> impl Responder {
    let user = form.into_inner().user;
}

fn main() {

    //key to encrypt and decrypt private cookie
    let cookie_secret = base64::decode(&env::var("COOKIE_SECRET_KEY").unwrap()).unwrap();

    server::new(|| {
        App::new().middleware(SessionStorage::new(CookieSessionBackend::private(&cookie_secret).secure(false))) //secure = false in order to test without TLS on localhost
            .route("/", Method::GET, home)
    })
        .bind("0.0.0.0:80").unwrap()
        .run()

        .route("/login", Method::GET, login_page)
        .route("/login", Method::POST, login_submit)

}

