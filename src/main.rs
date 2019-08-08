use actix_web::{server, HttpResponse, Responder};
use actix_web::http::{StatusCode, Method, header};

fn main() {
    server::new(|| {
        App::new().route("/", Method::GET, home)
    })
        .bind("0.0.0.0:80").unwrap()
        .run()
}

fn home(request: HttpRequest) -> impl Responder {
    HttpResponse::build(StatusCode::OK)
        .content_type("text/html; charset=utf-8")
        .body("Welcome Home!".to_string())
}