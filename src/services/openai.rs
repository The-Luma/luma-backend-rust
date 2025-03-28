use async_openai::{
    Client, 
    config::OpenAIConfig, 
    types::{
        CreateCompletionRequestArgs, 
        CreateEmbeddingRequestArgs, 
        CreateChatCompletionRequestArgs,
        ChatCompletionRequestSystemMessageArgs,
        ChatCompletionRequestUserMessageArgs,
        ChatCompletionRequestAssistantMessageArgs,
    }
};
use std::env;
use std::error::Error;

pub struct OpenAIService {
    pub client: Client<OpenAIConfig>,
    completion_model: String,
    chat_model: String,
    embedding_model: String,
}

impl OpenAIService {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // Get API key from environment
        let api_key = env::var("BACKEND_OPENAI_API_KEY")
            .expect("BACKEND_OPENAI_API_KEY must be set in environment");

        // Get optional organization ID from environment
        let org_id = env::var("BACKEND_OPENAI_ORG_ID").ok();

        // Get model names from environment (required)
        let completion_model = env::var("BACKEND_OPENAI_COMPLETION_MODEL")
            .expect("BACKEND_OPENAI_COMPLETION_MODEL must be set in environment");
        
        let chat_model = env::var("BACKEND_OPENAI_CHAT_MODEL")
            .expect("BACKEND_OPENAI_CHAT_MODEL must be set in environment");
        
        let embedding_model = env::var("BACKEND_OPENAI_EMBEDDING_MODEL")
            .expect("BACKEND_OPENAI_EMBEDDING_MODEL must be set in environment");

        // Create OpenAI configuration
        let mut config = OpenAIConfig::new()
            .with_api_key(api_key);

        // Add organization ID if provided
        if let Some(org) = org_id {
            config = config.with_org_id(&org);
        }

        // Initialize OpenAI client
        let client = Client::with_config(config);

        Ok(Self { 
            client,
            completion_model,
            chat_model,
            embedding_model,
        })
    }

    pub async fn check_connection(&self) -> Result<(), Box<dyn Error>> {
        self.client.models().list().await?;
        Ok(())
    }

    pub async fn create_completion(&self, prompt: &str, max_tokens: u32) -> Result<String, Box<dyn Error>> {
        let request = CreateCompletionRequestArgs::default()
            .model(&self.completion_model)
            .prompt(prompt)
            .max_tokens(max_tokens)
            .build()?;

        let response = self.client.completions().create(request).await?;
        
        // Return the first choice's text
        response.choices
            .first()
            .map(|choice| choice.text.clone())
            .ok_or_else(|| "No completion generated".into())
    }

    pub async fn create_chat_completion(&self, messages: Vec<(String, String)>, max_tokens: u32) -> Result<Option<String>, Box<dyn Error>> {
        let request = CreateChatCompletionRequestArgs::default()
            .model(&self.chat_model)
            .max_tokens(max_tokens)
            .messages(messages.into_iter().map(|(role, content)| {
                match role.to_lowercase().as_str() {
                    "system" => Ok(ChatCompletionRequestSystemMessageArgs::default()
                        .content(content)
                        .build()?
                        .into()),
                    "user" => Ok(ChatCompletionRequestUserMessageArgs::default()
                        .content(content)
                        .build()?
                        .into()),
                    "assistant" => Ok(ChatCompletionRequestAssistantMessageArgs::default()
                        .content(content)
                        .build()?
                        .into()),
                    _ => Err("Invalid role. Must be 'system', 'user', or 'assistant'".into()),
                }
            }).collect::<Result<Vec<_>, Box<dyn Error>>>()?)
            .build()?;

        let response = self.client.chat().create(request).await?;
        
        // Return the first choice's message content
        response.choices
            .first()
            .map(|choice| choice.message.content.clone())
            .ok_or_else(|| "No chat completion generated".into())
    }

    pub async fn create_embedding(&self, input: &str) -> Result<Vec<f32>, Box<dyn Error>> {
        let request = CreateEmbeddingRequestArgs::default()
            .model(&self.embedding_model)
            .input(input)
            .build()?;

        let response = self.client.embeddings().create(request).await?;
        
        // Return the first embedding vector
        response.data
            .first()
            .map(|data| data.embedding.clone())
            .ok_or_else(|| "No embedding generated".into())
    }

} 