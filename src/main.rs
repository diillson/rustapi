use actix_web::{middleware, web, App, HttpResponse, HttpServer, Responder};
use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web_prom::PrometheusMetricsBuilder;
//
use tracing_actix_web::TracingLogger;
use utoipa::OpenApi;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_swagger_ui::SwaggerUi;
mod doc;
mod config;
use serde_json::json;
use std::env;
use sqlx::{SqlitePool, Row};
use uuid::Uuid; mod auth; mod auth_middleware;

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug, PartialEq)]
enum TaskStatus {
    Todo,
    InProgress,
    Done,
}

impl TaskStatus {
    fn as_str(&self) -> &str {
        match self {
            TaskStatus::Todo => "Todo",
            TaskStatus::InProgress => "InProgress",
            TaskStatus::Done => "Done",
        }
    }

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "Todo" => Ok(TaskStatus::Todo),
            "InProgress" => Ok(TaskStatus::InProgress),
            "Done" => Ok(TaskStatus::Done),
            _ => Err(format!("Invalid status: {}", s)),
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
struct StatusHistory {
    status: TaskStatus,
    timestamp: DateTime<Utc>,
    note: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema, Clone, Debug)]
struct Task {
    id: String,
    title: String,
    description: String,
    status: TaskStatus,
    history: Vec<StatusHistory>,
}

#[derive(Deserialize, ToSchema, Debug)]
struct CreateTask {
    title: String,
    description: String,
}

#[derive(Deserialize, ToSchema, Debug)]
struct UpdateTask {
    title: Option<String>,
    description: Option<String>,
    status: Option<TaskStatus>,
    note: Option<String>,
}

#[derive(Deserialize, ToSchema, utoipa::IntoParams, Debug)]
struct TaskQuery {
    page: Option<u64>,
    limit: Option<u64>,
    title: Option<String>,
    status: Option<TaskStatus>,
}

struct AppState {
    db: SqlitePool,
}

#[utoipa::path(get, path = "/tasks", tag = "tasks", params(TaskQuery), responses((status = 200, description = "List tasks", body = Task)))]
#[actix_web::get("/tasks")]
#[tracing::instrument(name = "get_tasks", skip(data))]
async fn get_tasks(_: auth_middleware::AuthenticatedUser, data: web::Data<AppState>, query: web::Query<TaskQuery>) -> impl Responder {
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10);
    let offset = (page - 1) * limit;

    let mut sql = String::from("SELECT id, title, description, status, created_at FROM tasks WHERE id IS NOT NULL");
    let mut count_sql = String::from("SELECT COUNT(*) as count FROM tasks WHERE id IS NOT NULL");

    if query.title.is_some() {
        sql.push_str(" AND title LIKE ?");
        count_sql.push_str(" AND title LIKE ?");
    }

    if query.status.is_some() {
        sql.push_str(" AND status = ?");
        count_sql.push_str(" AND status = ?");
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");
    let mut query_builder = sqlx::query(&sql);
    let mut count_query_builder = sqlx::query(&count_sql);

    if let Some(title) = &query.title {
        let title_param = format!("%{}%", title);
        query_builder = query_builder.bind(title_param.clone());
        count_query_builder = count_query_builder.bind(title_param);
    }

    if let Some(status) = &query.status {
        query_builder = query_builder.bind(status.as_str());
        count_query_builder = count_query_builder.bind(status.as_str());
    }

    query_builder = query_builder.bind(limit as i64).bind(offset as i64);

    let rows = query_builder.fetch_all(&data.db).await;
    let count_row = count_query_builder.fetch_one(&data.db).await;

    match (rows, count_row) {
        (Ok(rows), Ok(count_row)) => {
            let mut tasks = Vec::new();
            for row in rows {
                let task_id: String = row.get("id");
                let title: String = row.get("title");
                let description: String = row.get("description");
                let status_str: String = row.get("status");
                
                let history = get_task_history(&data.db, &task_id).await.unwrap_or_else(|_| Vec::new());
                
                tasks.push(Task {
                    id: task_id,
                    title,
                    description,
                    status: TaskStatus::from_str(&status_str).unwrap(),
                    history,
                });
            }

            let total: i64 = count_row.get("count");
            HttpResponse::Ok().json(json!({
                "data": tasks,
                "meta": {
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "total_pages": (total as f64 / limit as f64).ceil() as u64
                }
            }))
        }
        _ => {
            eprintln!("Error fetching tasks");
            HttpResponse::InternalServerError().body("Database error")
        }
    }
}
#[tracing::instrument(name = "get_task_history", skip(db))]
async fn get_task_history(db: &SqlitePool, task_id: &str) -> Result<Vec<StatusHistory>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT status, timestamp, note FROM task_history WHERE task_id = ? ORDER BY timestamp ASC",
        task_id
    )
    .fetch_all(db)
    .await?;

    let mut history = Vec::new();
    for row in rows {
        history.push(StatusHistory {
            status: TaskStatus::from_str(&row.status).unwrap(),
            timestamp: DateTime::parse_from_rfc3339(&row.timestamp).unwrap().with_timezone(&Utc),
            note: row.note.clone(),
        });
    }
    Ok(history)
}

#[utoipa::path(get, path = "/tasks/{id}", tag = "tasks", responses((status = 200, description = "Get task", body = Task), (status = 404, description = "Task not found")))]
#[actix_web::get("/tasks/{id}")]
#[tracing::instrument(name = "get_task", skip(data))]
async fn get_task(_: auth_middleware::AuthenticatedUser, path: web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    let task_id = path.into_inner();
    let row = sqlx::query!(
        "SELECT id, title, description, status, created_at FROM tasks WHERE id = ?",
        task_id
    )
    .fetch_optional(&data.db)
    .await;

    match row {
        Ok(Some(row)) => {
            let task_id = &row.id;
            let history = get_task_history(&data.db, task_id).await.unwrap_or_else(|_| Vec::new());
            
            let task = Task {
                id: row.id.clone(),
                title: row.title.clone(),
                description: row.description.clone(),
                status: TaskStatus::from_str(&row.status).unwrap(),
                history,
            };
            HttpResponse::Ok().json(task)
        }
        Ok(None) => HttpResponse::NotFound().body("Tarefa não encontrada"),
        Err(e) => {
            eprintln!("Error fetching task: {}", e);
            HttpResponse::InternalServerError().body("Database error")
        }
    }
}

#[utoipa::path(post, path = "/tasks", tag = "tasks", request_body = CreateTask, responses((status = 201, description = "Task created", body = Task)))]
#[actix_web::post("/tasks")]
#[tracing::instrument(name = "create_task", skip(data))]
async fn create_task(_: auth_middleware::AuthenticatedUser, new_task: web::Json<CreateTask>, data: web::Data<AppState>) -> impl Responder {
    let task_id = Uuid::new_v4().to_string();
    let initial_status = TaskStatus::Todo;
    let initial_status_str = initial_status.as_str();
    let now = Utc::now();
    let now_str = now.to_rfc3339();
    let title = &new_task.title;
    let description = &new_task.description;

    let result = sqlx::query!(
        "INSERT INTO tasks (id, title, description, status, created_at) VALUES (?, ?, ?, ?, ?)",
        task_id,
        title,
        description,
        initial_status_str,
        now_str
    )
    .execute(&data.db)
    .await;

    if let Err(e) = result {
        eprintln!("Error creating task: {}", e);
        return HttpResponse::InternalServerError().body("Database error");
    }

    let note_str = "Tarefa criada";
    let history_result = sqlx::query!(
        "INSERT INTO task_history (task_id, status, timestamp, note) VALUES (?, ?, ?, ?)",
        task_id,
        initial_status_str,
        now_str,
        note_str
    )
    .execute(&data.db)
    .await;

    if let Err(e) = history_result {
        eprintln!("Error creating history: {}", e);
    }

    let task = Task {
        id: task_id,
        title: new_task.title.clone(),
        description: new_task.description.clone(),
        status: initial_status.clone(),
        history: vec![StatusHistory {
            status: initial_status,
            timestamp: now,
            note: Some(note_str.to_string()),
        }],
    };

    HttpResponse::Created().json(task)
}

#[utoipa::path(put, path = "/tasks/{id}", tag = "tasks", request_body = UpdateTask, responses((status = 200, description = "Task updated", body = Task), (status = 404, description = "Task not found")))]
#[actix_web::put("/tasks/{id}")]
#[tracing::instrument(name = "update_task", skip(data))]
async fn update_task(
    _: auth_middleware::AuthenticatedUser,
    path: web::Path<String>,
    updated_task: web::Json<UpdateTask>,
    data: web::Data<AppState>,
) -> impl Responder {
    let task_id = path.into_inner();

    let current_task = sqlx::query!(
        "SELECT id, title, description, status, created_at FROM tasks WHERE id = ?",
        task_id
    )
    .fetch_optional(&data.db)
    .await;

    let current_task = match current_task {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::NotFound().body("Tarefa não encontrada"),
        Err(e) => {
            eprintln!("Error fetching task: {}", e);
            return HttpResponse::InternalServerError().body("Database error");
        }
    };

    let mut new_title = current_task.title.clone();
    let mut new_description = current_task.description.clone();
    let mut new_status = TaskStatus::from_str(&current_task.status).unwrap();

    if let Some(title) = &updated_task.title {
        new_title = title.clone();
    }
    if let Some(description) = &updated_task.description {
        new_description = description.clone();
    }

    let mut status_changed = false;
    if let Some(status) = &updated_task.status {
        if *status != new_status {
            new_status = status.clone();
            status_changed = true;
        }
    }

    let new_status_str = new_status.as_str();
    let update_result = sqlx::query!(
        "UPDATE tasks SET title = ?, description = ?, status = ? WHERE id = ?",
        new_title,
        new_description,
        new_status_str,
        task_id
    )
    .execute(&data.db)
    .await;

    if let Err(e) = update_result {
        eprintln!("Error updating task: {}", e);
        return HttpResponse::InternalServerError().body("Database error");
    }

    if status_changed {
        let now = Utc::now().to_rfc3339();
        let note = updated_task.note.clone().unwrap_or_else(|| "Status atualizado".to_string());

        let history_result = sqlx::query!(
            "INSERT INTO task_history (task_id, status, timestamp, note) VALUES (?, ?, ?, ?)",
            task_id,
            new_status_str,
            now,
            note
        )
        .execute(&data.db)
        .await;

        if let Err(e) = history_result {
            eprintln!("Error creating history: {}", e);
        }
    }

    let history = get_task_history(&data.db, &task_id).await.unwrap_or_else(|_| Vec::new());

    let task = Task {
        id: task_id,
        title: new_title,
        description: new_description,
        status: new_status,
        history,
    };

    HttpResponse::Ok().json(task)
}

#[utoipa::path(delete, path = "/tasks/{id}", tag = "tasks", responses((status = 204, description = "Task deleted"), (status = 404, description = "Task not found")))]
#[actix_web::delete("/tasks/{id}")]
#[tracing::instrument(name = "delete_task", skip(data))]
async fn delete_task(_: auth_middleware::AuthenticatedUser, path: web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    let task_id = path.into_inner();

    let result = sqlx::query!("DELETE FROM tasks WHERE id = ?", task_id)
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
                HttpResponse::NoContent().finish()
            } else {
                HttpResponse::NotFound().body("Tarefa não encontrada")
            }
        }
        Err(e) => {
            eprintln!("Error deleting task: {}", e);
            HttpResponse::InternalServerError().body("Database error")
        }
    }
}

#[utoipa::path(get, path = "/health", tag = "health", responses((status = 200, description = "Health check")))]
#[actix_web::get("/health")]
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "ok",
        "timestamp": Utc::now().to_rfc3339()
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .json()
        .init();

    let settings = config::Settings::new().expect("Failed to load configuration");

    if settings.security.jwt_secret.is_empty() {
        eprintln!("❌ ERRO: JWT_SECRET não configurado. Defina um secret forte em produção.");
        std::process::exit(1);
    }

    std::env::set_var("JWT_SECRET", &settings.security.jwt_secret);

    let database_url = settings.database.url;

    let pool = SqlitePool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    // Habilita WAL no SQLite para melhor concorrência
    sqlx::query("PRAGMA journal_mode=WAL;")
        .execute(&pool)
        .await
        .expect("Failed to enable WAL");

    let host = settings.server.host;
    let port = settings.server.port;

    let app_state = web::Data::new(AppState { db: pool });

    let enable_swagger = settings.security.enable_swagger;

    // Configuração de Rate Limiting (Governor)
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(10) // 10 requests por segundo por IP
        .burst_size(20)
        .finish()
        .unwrap();

    // Configuração de Métricas (Prometheus)
    let prometheus = PrometheusMetricsBuilder::new("api_rust")
        .endpoint("/metrics")
        .build()
        .unwrap();

    println!("🚀 Servidor iniciado em http://{}:{}", host, port);
    if enable_swagger {
        println!("📚 Swagger UI habilitado em /swagger-ui/");
    } else {
        println!("⚠ Swagger UI desabilitado (produção)");
    }

    HttpServer::new(move || {
        let mut app = App::new()
            .wrap(tracing_actix_web::TracingLogger::default())
            .wrap(prometheus.clone())
            .wrap(Governor::new(&governor_conf))
            .wrap(middleware::DefaultHeaders::new()
                .add(("X-Content-Type-Options", "nosniff"))
                .add(("X-Frame-Options", "DENY"))
                .add(("X-XSS-Protection", "1; mode=block"))
                .add(("Referrer-Policy", "no-referrer"))
                .add(("Permissions-Policy", "geolocation=(), microphone=(), camera=()")))
            .wrap(Cors::default()
                .allowed_origin("http://localhost:3000")
                .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                .allowed_headers(vec!["Authorization", "Content-Type"])
                .max_age(3600))
            .app_data(app_state.clone())
            .service(get_tasks)
            .service(get_task)
            .service(create_task)
            .service(update_task)
            .service(delete_task)
            .service(health_check)
            .route("/auth/register", web::post().to(auth::register))
            .route("/auth/login", web::post().to(auth::login));

        if enable_swagger {
            app = app.service(SwaggerUi::new("swagger-ui/{tail:.}").url("/api-doc/openapi.json", doc::ApiDoc::openapi()));
        }

        app
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}
