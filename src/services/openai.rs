use async_openai::{
    Client, 
    config::OpenAIConfig, 
    types::{
        CreateChatCompletionRequestArgs,
        ChatCompletionRequestSystemMessageArgs,
        ChatCompletionRequestUserMessageArgs,
        ChatCompletionRequestAssistantMessageArgs,
        ChatCompletionToolArgs,
        ChatCompletionToolType,
        FunctionObject,
        ChatCompletionRequestToolMessageArgs
    }
};
use std::error::Error;
use crate::config::Config;
use serde_json::json;
use crate::services::pinecone_ie::PineconeIEService;
#[derive(Clone)]
pub struct OpenAIService {
    pub client: Client<OpenAIConfig>,
    // completion_model: String,
    chat_model: String,
    // embedding_model: String,
    // embedding_dimensions: u32,
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
            chat_model: config.openai_chat_model.clone(),
            // completion_model: config.openai_completion_model.clone(),
            // embedding_model: config.openai_embedding_model.clone(),
            // embedding_dimensions: config.openai_embedding_dimensions,
        })
    }

    pub async fn check_connection(&self) -> Result<(), Box<dyn Error>> {
        println!("-------------------------------------");
        println!("Testing OpenAI connection...");
        self.client.models().list().await?;
        println!("Successfully connected to OpenAI");
        Ok(())
    }

    // pub async fn create_completion(&self, prompt: &str, max_tokens: u32) -> Result<String, Box<dyn Error>> {
    //     let request = CreateCompletionRequestArgs::default()
    //         .model(&self.completion_model)
    //         .prompt(prompt)
    //         .max_tokens(max_tokens)
    //         .build()?;
    //
    //     let response = self.client.completions().create(request).await?;
    //
    //     // Return the first choice's text
    //     response.choices
    //         .first()
    //         .map(|choice| choice.text.clone())
    //         .ok_or_else(|| "No completion generated".into())
    // }

    // pub async fn create_chat_completion(&self, messages: Vec<(String, String)>, max_tokens: u32) -> Result<Option<String>, Box<dyn Error>> {
    //     let request = CreateChatCompletionRequestArgs::default()
    //         .model(&self.chat_model)
    //         .max_tokens(max_tokens)
    //         .messages(messages.into_iter().map(|(role, content)| {
    //             match role.to_lowercase().as_str() {
    //                 "system" => Ok(ChatCompletionRequestSystemMessageArgs::default()
    //                     .content(content)
    //                     .build()?
    //                     .into()),
    //                 "user" => Ok(ChatCompletionRequestUserMessageArgs::default()
    //                     .content(content)
    //                     .build()?
    //                     .into()),
    //                 "assistant" => Ok(ChatCompletionRequestAssistantMessageArgs::default()
    //                     .content(content)
    //                     .build()?
    //                     .into()),
    //                 _ => Err("Invalid role. Must be 'system', 'user', or 'assistant'".into()),
    //             }
    //         }).collect::<Result<Vec<_>, Box<dyn Error>>>()?)
    //         .build()?;
    //
    //     let response = self.client.chat().create(request).await?;
    //
    //     // Return the first choice's message content
    //     response.choices
    //         .first()
    //         .map(|choice| choice.message.content.clone())
    //         .ok_or_else(|| "No chat completion generated".into())
    // }

    // pub async fn create_embedding(&self, input: &str) -> Result<Vec<f32>, Box<dyn Error>> {
    //     let request = CreateEmbeddingRequestArgs::default()
    //         .model(&self.embedding_model)
    //         .dimensions(self.embedding_dimensions)
    //         .input(input)
    //         .build()?;
    //
    //     let response = self.client.embeddings().create(request).await?;
    //
    //     // Return the first embedding vector
    //     response.data
    //         .first()
    //         .map(|data| data.embedding.clone())
    //         .ok_or_else(|| "No embedding generated".into())
    // }

    pub async fn create_chat_completion_with_vector_search(
        &self,
        messages: Vec<(String, String)>,
        last_message: &str,
        namespace_id: &str,
        max_tokens: u32,
        pinecone_service: &PineconeIEService,
    ) -> Result<String, Box<dyn Error>> {
        // Create the initial request with function definition
        let request = CreateChatCompletionRequestArgs::default()
            .model(&self.chat_model)
            .max_tokens(max_tokens)
            .messages(messages.iter().map(|(role, content)| {
                match role.to_lowercase().as_str() {
                    "system" => Ok(ChatCompletionRequestSystemMessageArgs::default()
                        .content(content.as_str())
                        .build()?
                        .into()),
                    "user" => Ok(ChatCompletionRequestUserMessageArgs::default()
                        .content(content.as_str())
                        .build()?
                        .into()),
                    "assistant" => Ok(ChatCompletionRequestAssistantMessageArgs::default()
                        .content(content.as_str())
                        .build()?
                        .into()),
                    _ => Err("Invalid role. Must be 'system', 'user', or 'assistant'".into()),
                }
            }).collect::<Result<Vec<_>, Box<dyn Error>>>()?)
            .tools([ChatCompletionToolArgs::default()
                .r#type(ChatCompletionToolType::Function)
                .function(FunctionObject {
                    name: "search_knowledge_base".to_string(),
                    description: Some("Search the knowledge base for relevant information".to_string()),
                    parameters: Some(json!({
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "The search query to find relevant information",
                            },
                            "top_k": {
                                "type": "integer",
                                "description": "Number of results to return",
                                "default": 10
                            }
                        },
                        "required": ["query"],
                    })),
                    strict: Some(false),
                })
                .build()?])
            .tool_choice("auto")
            .build()?;

        let response = self.client.chat().create(request).await?;
        let response_message = response.choices.first()
            .ok_or("No response from OpenAI")?
            .message.clone();

        // If the model wants to call a function
        if let Some(tool_calls) = response_message.tool_calls {
            if let Some(tool_call) = tool_calls.first() {
                if tool_call.function.name == "search_knowledge_base" {
                    // Parse the function arguments
                    let args: serde_json::Value = serde_json::from_str(&tool_call.function.arguments)?;
                    let query = args["query"].as_str().ok_or("Missing query parameter")?;
                    let top_k = args["top_k"].as_i64().unwrap_or(3) as i32;

                    // Search Pinecone IE
                    let search_results = match pinecone_service.search(
                        namespace_id,
                        top_k,
                        Some(query.to_string())
                    ).await {
                        Ok(results) => results,
                        Err(e) => {
                            return Err(e);
                        }
                    };

                    // Format the search results
                    let mut context = String::from("Here is the relevant information from the knowledge base:\n\n");
                    
                    // Access the hits directly from the search response
                    for (i, hit) in search_results.result.hits.iter().enumerate() {
                        context.push_str(&format!("{}. {}\n\n", i + 1, hit.fields.text));
                    }

                    // Add the assistant's message with tool calls
                    let assistant_message = ChatCompletionRequestAssistantMessageArgs::default()
                        .content(response_message.content.unwrap_or_default())
                        .tool_calls([tool_call.clone()])
                        .build()?;
                    
                    // Add the tool response
                    let tool_message = ChatCompletionRequestToolMessageArgs::default()
                        .content(context)
                        .tool_call_id(tool_call.id.clone())
                        .build()?;
                    
                    // Add the user's follow-up message
                    let user_message = ChatCompletionRequestUserMessageArgs::default()
                        .content(last_message)
                        .build()?;
                    
                    // Get final response from the model
                    let final_request = CreateChatCompletionRequestArgs::default()
                        .model(&self.chat_model)
                        .max_tokens(max_tokens)
                        .messages([
                            assistant_message.into(),
                            tool_message.into(),
                            user_message.into(),
                        ])
                        .build()?;

                    let final_response = self.client.chat().create(final_request).await?;
                    return Ok(final_response.choices.first()
                        .ok_or("No response from OpenAI")?
                        .message.content
                        .clone()
                        .ok_or("No content in response")?);
                }
            }
        }

        // If no function call was made, return the original response
        Ok(response_message.content.ok_or("No content in response")?)
    }
} 