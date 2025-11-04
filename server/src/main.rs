use actix_web::{App, HttpResponse, HttpServer, Responder, web};

async fn health_check() -> impl Responder {
    HttpResponse::Ok().body("Server is alive")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server on http://localhost:3000");
    HttpServer::new(|| App::new().route("/health", web::get().to(health_check)))
        .bind(("0.0.0.0", 3000))?
        .run()
        .await
}
