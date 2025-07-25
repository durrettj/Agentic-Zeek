#handle generating text embeddings using the Gemini API
from google import genai
from google.genai import types
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

class EmbeddingService:
    def __init__(self, api_key: str, model_name: str = "gemini-embedding-001"):
        """
        Initializes the EmbeddingService with a Gemini API key and model name.
        """
        if not api_key:
            raise ValueError("GEMINI_API_KEY must be provided for EmbeddingService.")
        
        # Initialize the Gemini client. For Vertex AI specific features like logprobs,
        # client = genai.Client(vertexai=True, project=PROJECT_ID, location="global") would be used.
        # For general Gemini API, direct initialization is fine.
        self.client = genai.Client(api_key=api_key)
        self.model_name = model_name
        logger.info(f"EmbeddingService initialized with model: {self.model_name}")

    async def generate_embeddings(self, texts: List[str], task_type: str = "CLUSTERING", output_dimensionality: Optional[int] = None) -> Optional[List[List[float]]]:
        """
        Generates embeddings for a list of text inputs using the Gemini API.
        [3]
        
        Args:
            texts: A list of strings to embed.
            task_type: The task type for embedding optimization (e.g., "CLUSTERING", "SEMANTIC_SIMILARITY").
                       "CLUSTERING" is recommended for anomaly detection.
            output_dimensionality: Optional. The desired output dimension (e.g., 768, 1536).
                                   If None, uses the model's default (3072 for gemini-embedding-001).
        
        Returns:
            A list of embedding vectors, where each vector is a list of floats.
            Returns None if an error occurs.
        """
        if not texts:
            return

        embed_config = types.EmbedContentConfig(task_type=task_type)
        if output_dimensionality:
            embed_config.output_dimensionality = output_dimensionality

        try:
            result = await self.client.models.embed_content_async(
                model=self.model_name,
                contents=texts,
                config=embed_config
            )
            embeddings = [e.values for e in result.embeddings]
            logger.debug(f"Generated {len(embeddings)} embeddings, each with dimension: {len(embeddings)}")
            return embeddings
        except Exception as e:
            logger.error(f"Error generating embeddings: {e}", exc_info=True)
            return None
