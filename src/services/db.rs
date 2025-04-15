use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Error;
use crate::config::Config;

/// Initializes and returns a PostgreSQL connection pool.
pub async fn init_db_pool(config: &Config) -> Result<PgPool, Error> {
    // Create and return the connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.backend_db_connection)
        .await?;
    
    println!("Successfully connected to database");
    Ok(pool)
}

pub async fn run_test_query(pool: &PgPool) -> Result<(), Error> {
    println!("-------------------------------------");
    println!("Testing PostgreSQL connection...");
    
    // Use a specific type (i64) instead of letting it default to the unit type
    let _result: i64 = sqlx::query_scalar("SELECT $1")
        .bind(150_i64)
        .fetch_one(pool)
        .await?;

    println!("Successfully connected to PostgreSQL");
    Ok(())
}