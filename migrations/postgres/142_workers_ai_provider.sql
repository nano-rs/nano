-- Add Cloudflare Workers AI as a provider for running open models (Gemma, Llama, Mistral)
-- on Cloudflare's edge infrastructure. API key is optional when the AI Gateway and Workers AI
-- share the same Cloudflare account.
INSERT INTO provider_credentials (provider, display_name, config, enabled)
VALUES ('workers-ai', 'Workers AI', '{}', false)
ON CONFLICT (provider) DO NOTHING;
