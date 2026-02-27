use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use tower_http::cors::{Any, CorsLayer};

#[derive(Serialize, sqlx::FromRow)]
struct Server {
    address: String,
    world_id: Option<i64>,
    name: String,
    description: Option<String>,
    status: Option<String>,
    topic_status: Option<serde_json::Value>,
    players: i32,
    updated_at: NaiveDateTime,
}

#[derive(Serialize, sqlx::FromRow)]
struct PlayerHistoryPoint {
    players: i32,
    recorded_at: NaiveDateTime,
}

#[derive(Deserialize)]
struct HistoryQuery {
    // Unix timestamp
    since: Option<i64>,
}

#[derive(Deserialize)]
struct StatsQuery {
    // day, week, month, year, all
    period: Option<String>,
}

#[derive(Serialize)]
struct HistoryPoint {
    timestamp: NaiveDateTime,
    players: f64,
}

#[derive(Serialize)]
struct ServerStats {
    period: String,
    total_records: i64,
    avg_players: f64,
    max_players: i32,
    min_players: i32,
    // Sunday=0 through Saturday=6
    weekday_averages: [f64; 7],
    // 0-23
    hourly_averages: [f64; 24],
    // Time series for charting
    history: Vec<HistoryPoint>,
}

#[derive(sqlx::FromRow)]
struct BasicStats {
    count: Option<i64>,
    avg: Option<f64>,
    max: Option<i32>,
    min: Option<i32>,
}

#[derive(sqlx::FromRow)]
struct GroupedAvg {
    group_key: Option<f64>,
    avg: Option<f64>,
}

#[derive(sqlx::FromRow)]
struct BucketedHistory {
    bucket: Option<NaiveDateTime>,
    avg: Option<f64>,
}

// Custom JSON response that doesn't escape HTML
struct RawJson<T>(T);

impl<T: Serialize> IntoResponse for RawJson<T> {
    fn into_response(self) -> Response {
        let mut buf = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
        self.0.serialize(&mut ser).unwrap();
        (
            [(header::CONTENT_TYPE, "application/json")],
            buf,
        ).into_response()
    }
}

async fn get_servers(State(pool): State<PgPool>) -> Result<RawJson<Vec<Server>>, StatusCode> {
    let servers = sqlx::query_as::<_, Server>(
        "SELECT address, world_id, name, description, status, topic_status, players, updated_at FROM servers ORDER BY players DESC",
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(RawJson(servers))
}

async fn get_server(
    State(pool): State<PgPool>,
    Path((ip, port)): Path<(String, u16)>,
) -> Result<RawJson<Server>, StatusCode> {
    let address = format!("{}:{}", ip, port);
    let server = sqlx::query_as::<_, Server>(
        "SELECT address, world_id, name, description, status, topic_status, players, updated_at FROM servers WHERE address = $1",
    )
    .bind(&address)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(RawJson(server))
}

async fn get_server_history(
    State(pool): State<PgPool>,
    Path((ip, port)): Path<(String, u16)>,
    Query(query): Query<HistoryQuery>,
) -> Result<RawJson<Vec<PlayerHistoryPoint>>, StatusCode> {
    let address = format!("{}:{}", ip, port);
    let since = query
        .since
        .and_then(|ts| DateTime::from_timestamp(ts, 0))
        .map(|dt| dt.naive_utc())
        .unwrap_or_else(|| Utc::now().naive_utc() - chrono::Duration::hours(24));

    let history = sqlx::query_as::<_, PlayerHistoryPoint>(
        "SELECT players, recorded_at FROM player_history WHERE address = $1 AND recorded_at > $2 ORDER BY recorded_at ASC",
    )
    .bind(&address)
    .bind(since)
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(RawJson(history))
}

async fn get_server_stats(
    State(pool): State<PgPool>,
    Path((ip, port)): Path<(String, u16)>,
    Query(query): Query<StatsQuery>,
) -> Result<RawJson<ServerStats>, StatusCode> {
    let address = format!("{}:{}", ip, port);
    let period = query.period.as_deref().unwrap_or("day");

    let since = match period {
        "day" => Some(Utc::now().naive_utc() - chrono::Duration::days(1)),
        "week" => Some(Utc::now().naive_utc() - chrono::Duration::weeks(1)),
        "month" => Some(Utc::now().naive_utc() - chrono::Duration::days(30)),
        "year" => Some(Utc::now().naive_utc() - chrono::Duration::days(365)),
        "all" => None,
        _ => Some(Utc::now().naive_utc() - chrono::Duration::days(1)),
    };

    // Basic stats query
    let basic_stats = if let Some(since_time) = since {
        sqlx::query_as::<_, BasicStats>(
            "SELECT COUNT(*) as count, AVG(players)::float8 as avg, MAX(players) as max, MIN(players) as min
             FROM player_history WHERE address = $1 AND recorded_at > $2"
        )
        .bind(&address)
        .bind(since_time)
        .fetch_one(&pool)
        .await
    } else {
        sqlx::query_as::<_, BasicStats>(
            "SELECT COUNT(*) as count, AVG(players)::float8 as avg, MAX(players) as max, MIN(players) as min
             FROM player_history WHERE address = $1"
        )
        .bind(&address)
        .fetch_one(&pool)
        .await
    }.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Weekday averages (0=Sunday, 6=Saturday)
    let weekday_rows = if let Some(since_time) = since {
        sqlx::query_as::<_, GroupedAvg>(
            "SELECT EXTRACT(DOW FROM recorded_at)::float8 as group_key, AVG(players)::float8 as avg
             FROM player_history WHERE address = $1 AND recorded_at > $2
             GROUP BY EXTRACT(DOW FROM recorded_at) ORDER BY group_key"
        )
        .bind(&address)
        .bind(since_time)
        .fetch_all(&pool)
        .await
    } else {
        sqlx::query_as::<_, GroupedAvg>(
            "SELECT EXTRACT(DOW FROM recorded_at)::float8 as group_key, AVG(players)::float8 as avg
             FROM player_history WHERE address = $1
             GROUP BY EXTRACT(DOW FROM recorded_at) ORDER BY group_key"
        )
        .bind(&address)
        .fetch_all(&pool)
        .await
    }.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut weekday_averages = [0.0; 7];
    for row in weekday_rows {
        if let (Some(key), Some(avg)) = (row.group_key, row.avg) {
            let idx = key as usize;
            if idx < 7 {
                weekday_averages[idx] = avg;
            }
        }
    }

    // Hourly averages (0-23)
    let hourly_rows = if let Some(since_time) = since {
        sqlx::query_as::<_, GroupedAvg>(
            "SELECT EXTRACT(HOUR FROM recorded_at)::float8 as group_key, AVG(players)::float8 as avg
             FROM player_history WHERE address = $1 AND recorded_at > $2
             GROUP BY EXTRACT(HOUR FROM recorded_at) ORDER BY group_key"
        )
        .bind(&address)
        .bind(since_time)
        .fetch_all(&pool)
        .await
    } else {
        sqlx::query_as::<_, GroupedAvg>(
            "SELECT EXTRACT(HOUR FROM recorded_at)::float8 as group_key, AVG(players)::float8 as avg
             FROM player_history WHERE address = $1
             GROUP BY EXTRACT(HOUR FROM recorded_at) ORDER BY group_key"
        )
        .bind(&address)
        .fetch_all(&pool)
        .await
    }.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut hourly_averages = [0.0; 24];
    for row in hourly_rows {
        if let (Some(key), Some(avg)) = (row.group_key, row.avg) {
            let idx = key as usize;
            if idx < 24 {
                hourly_averages[idx] = avg;
            }
        }
    }

    // Time-bucketed history for line charts
    // day: 30 min buckets, week: 1 hour, month: 6 hours, year/all: 1 day
    let history_rows = if let Some(since_time) = since {
        match period {
            "day" => {
                sqlx::query_as::<_, BucketedHistory>(
                    "SELECT date_trunc('hour', recorded_at) +
                            INTERVAL '30 minutes' * (EXTRACT(MINUTE FROM recorded_at)::int / 30) as bucket,
                            AVG(players)::float8 as avg
                     FROM player_history WHERE address = $1 AND recorded_at > $2
                     GROUP BY bucket ORDER BY bucket ASC"
                )
                .bind(&address)
                .bind(since_time)
                .fetch_all(&pool)
                .await
            }
            "week" => {
                sqlx::query_as::<_, BucketedHistory>(
                    "SELECT date_trunc('hour', recorded_at) as bucket, AVG(players)::float8 as avg
                     FROM player_history WHERE address = $1 AND recorded_at > $2
                     GROUP BY bucket ORDER BY bucket ASC"
                )
                .bind(&address)
                .bind(since_time)
                .fetch_all(&pool)
                .await
            }
            "month" => {
                sqlx::query_as::<_, BucketedHistory>(
                    "SELECT date_trunc('hour', recorded_at) +
                            INTERVAL '6 hours' * (EXTRACT(HOUR FROM recorded_at)::int / 6) as bucket,
                            AVG(players)::float8 as avg
                     FROM player_history WHERE address = $1 AND recorded_at > $2
                     GROUP BY bucket ORDER BY bucket ASC"
                )
                .bind(&address)
                .bind(since_time)
                .fetch_all(&pool)
                .await
            }
            _ => {
                sqlx::query_as::<_, BucketedHistory>(
                    "SELECT date_trunc('day', recorded_at) as bucket, AVG(players)::float8 as avg
                     FROM player_history WHERE address = $1 AND recorded_at > $2
                     GROUP BY bucket ORDER BY bucket ASC"
                )
                .bind(&address)
                .bind(since_time)
                .fetch_all(&pool)
                .await
            }
        }
    } else {
        sqlx::query_as::<_, BucketedHistory>(
            "SELECT date_trunc('day', recorded_at) as bucket, AVG(players)::float8 as avg
             FROM player_history WHERE address = $1
             GROUP BY bucket ORDER BY bucket ASC"
        )
        .bind(&address)
        .fetch_all(&pool)
        .await
    }.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let history: Vec<HistoryPoint> = history_rows
        .into_iter()
        .filter_map(|row| {
            Some(HistoryPoint {
                timestamp: row.bucket?,
                players: row.avg?,
            })
        })
        .collect();

    Ok(RawJson(ServerStats {
        period: period.to_string(),
        total_records: basic_stats.count.unwrap_or(0),
        avg_players: basic_stats.avg.unwrap_or(0.0),
        max_players: basic_stats.max.unwrap_or(0),
        min_players: basic_stats.min.unwrap_or(0),
        weekday_averages,
        hourly_averages,
        history,
    }))
}

#[tokio::main]
async fn main() {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any);

    let app = Router::new()
        .route("/servers", get(get_servers))
        .route("/servers/:ip/:port", get(get_server))
        .route("/servers/:ip/:port/history", get(get_server_history))
        .route("/servers/:ip/:port/stats", get(get_server_stats))
        .layer(cors)
        .with_state(pool);

    let addr = "0.0.0.0:3333";
    println!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
