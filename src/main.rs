use axum::{
    routing::get,
    Router,
};
async fn hello() -> &'static str {
    "Hello, Rust!"
}

#[tokio::main]
async fn main() {
    const ADDRESS: &str = "0.0.0.0:3000";

    // build our application with a single route
    let app = Router::new()
        .route("/", get(hello));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(ADDRESS).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    println!("Server running on http://{}", ADDRESS);
}