pub mod auth;
pub mod users;
pub mod chat;
pub mod utils;

pub use utils::{
    error_response,
};

pub use auth::{
    check_admin_setup,
    create_admin,
    login,
    refresh_token,
    logout,
    create_invitation,
    register_with_invitation,
};

pub use users::{
    me,
    get_user_by_id,
    search_users,
    delete_account,
    admin_delete_user
};

pub use chat::{
    start_chat,
    send_message,
    get_chat_history,
    list_conversations,
    delete_conversation,
    create_namespace,
    list_namespaces,
    delete_namespace,
    share_namespace,
    revoke_namespace_access,
    upload_document,
    delete_document,
    list_documents
};