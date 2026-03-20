package com.example.security.config;

import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.model.openai.OpenAiChatModel;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ChatModelFactory {

    private final String modelName;

    public ChatModelFactory(
            @Value("${langchain4j.open-ai.chat-model.model-name:gpt-4o-mini}") String modelName) {
        this.modelName = modelName;
    }

    public ChatLanguageModel create(String apiKey) {
        return OpenAiChatModel.builder()
                .apiKey(apiKey)
                .modelName(modelName)
                .build();
    }
}
