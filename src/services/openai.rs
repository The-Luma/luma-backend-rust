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
use std::error::Error;
use crate::config::Config;

#[derive(Clone)]
pub struct OpenAIService {
    pub client: Client<OpenAIConfig>,
    completion_model: String,
    chat_model: String,
    embedding_model: String,
}

impl OpenAIService {
    pub fn new(config: &Config) -> Result<Self, Box<dyn Error>> {
        // Create OpenAI configuration
        let mut openai_config = OpenAIConfig::new()
            .with_api_key(&config.openai_api_key);

        // Add organization ID if provided
        if !config.openai_org_id.is_empty() {
            openai_config = openai_config.with_org_id(&config.openai_org_id);
        }

        // Create OpenAI client
        let client = Client::with_config(openai_config);

        Ok(Self {
            client,
            completion_model: config.openai_completion_model.clone(),
            chat_model: config.openai_chat_model.clone(),
            embedding_model: config.openai_embedding_model.clone(),
        })
    }

    pub async fn check_connection(&self) -> Result<(), Box<dyn Error>> {
        println!("-------------------------------------");
        println!("Testing OpenAI connection...");
        self.client.models().list().await?;
        println!("Successfully connected to OpenAI");
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