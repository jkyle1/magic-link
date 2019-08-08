use actix_web::{server, HttpResponse, Responder, HttpRequest, App, Result, Form, AsyncResponder};
use actix_web::http::{StatusCode, Method, header};
use actix_web::middleware::session::{CookieSessionBackend, SessionStorage, RequestSession};
use base64;
use std::env;
use rand::rngs::{OsRng};
use rand::RngCore;
use serde::Serialize;
use futures::prelude::*;
use failure::Fail;
use approveapi::{CreatePromptRequest, ApproveApi};


#[derive(Deserialize)]
struct LoginForm {
    user: String, //email or phone
}

fn random_challenge() -> String {
    let mut nonce = vec![0u8; 32];
    OsRng::new().unwrap().fill_bytes(&mut nonce);
    base64::encode_config(&nonce, base64::URL_SAFE)
}

#[derive(Serialize, Deserialize)]
struct LoginChallenge {
    user: String,
    challenge: String,
}

#[derive(Debug, Fail)]
#[fail(display = "Internal Server Error Occurred")]
struct ServerError(String);
impl actix_web::ResponseError for ServerError {}

fn send_magic_link(user: String, challenge_token: String) -> impl Future<Item=(), Error=ServerError> {
    let client = approveapi::create_client(env::var("APPROVEAPI_TEST_KEY").unwrap());
    let mut prompt_request = CreatePromptRequest::new(user,
                                                      r#"Click the link below to sign in to your account.  This link will expire in 24 hours."#.to_string(),
    );
    prompt_request.title = Some("Magic sign-in link".to_string());
    prompt_request.approve_text = Some("Sign-in".to_string());
    prompt_request.approve_redirect_url = Some(format!("http://localhost/verify_login?c={}", challenge_token));

    client.create_prompt(prompt_request).map_err(|e| {
        eprintln!("approveapi error: {:?}", e);
        ServerError(format!("approveapi error: {:?}", e))
    })
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
    let challenge = random_challenge();

    //store LoginChallenge in session cookie
    let _ = request.session().set("pending_login_challenge", LoginChallenge {
        user: user.clone(),
        challenge: challenge.clone(),
    });
    //advise the user to check their email or phone for the link
    send_magic_link(user, challenge).and_then(|_| {
        Ok("Check your email or phone for a magic link to sign in!".to_string())
    }).responder()
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

