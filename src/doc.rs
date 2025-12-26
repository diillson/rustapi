use utoipa::OpenApi;

use crate::auth;
use crate::{CreateTask, StatusHistory, Task, TaskQuery, TaskStatus, UpdateTask};

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::get_tasks,
        crate::get_task,
        crate::create_task,
        crate::update_task,
        crate::delete_task,
        crate::health_check,
        auth::register,
        auth::login
    ),
    components(
        schemas(
            Task,
            CreateTask,
            UpdateTask,
            TaskQuery,
            TaskStatus,
            StatusHistory,
            auth::RegisterUser,
            auth::LoginUser
        )
    )
)]
pub struct ApiDoc;