use dotenv::dotenv;
use std::env;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Error;

/// Initializes and returns a PostgreSQL connection pool.
pub async fn init_db_pool() -> Result<PgPool, Error> {
    // Load environment variables from the .env file
    dotenv().ok();

    // Retrieve the DB_CONNECTION variable from the environment
    let database_url = env::var("DB_CONNECTION")
        .expect("DB_CONNECTION must be set in the .env file");

    // Create and return the connection pool
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
}

pub async fn run_test_query(pool: &PgPool) -> Result<(), Error> {
    let row: (i64,) = sqlx::query_as("SELECT $1")
        .bind(150_i64)
        .fetch_one(pool)
        .await?;

    println!("PostgreSQL Connectivity. Test query (SELECT $1) returned: {}", row.0);
    Ok(())
}