// Inference connection presentation metadata. This is intentionally a small,
// declarative catalog: availability is always reported by the host probes.

export const inferenceRoleLabel = {
  language: 'Task model', embedding: 'Memory embeddings',
  transcription: 'Speech to text', speech: 'Text to speech',
};

export function inferenceRoleForName(name) {
  return ({ embed: 'embedding', transcribe: 'transcription', speak: 'speech' })[name] || 'language';
}

export const inferenceProviders = {
  language: [['claude-code', 'Claude Code (subscription)'], ['codex', 'ChatGPT subscription (Codex)'], ['grok-code', 'Grok subscription (Grok Build)'], ['anthropic', 'Anthropic API'], ['openai', 'OpenAI compatible'], ['xai', 'xAI'], ['ollama', 'Ollama (local)']],
  embedding: [['ollama', 'Ollama (local)'], ['hash', 'Built-in lexical index']],
  transcription: [['apple-speech', 'Apple Speech (local)'], ['whisper-cpp', 'whisper.cpp (local)'], ['openai', 'OpenAI compatible']],
  speech: [['openai', 'OpenAI compatible / Kokoro'], ['apple-speech', 'Apple Speech (local)'], ['macos-say', 'macOS voices']],
};

// Curated, understandable defaults—not an availability claim. Every remote
// provider still offers Custom because account access and compatible servers
// vary; local engines especially may use any installed model identifier.
export const inferenceModels = {
  language: {
    'claude-code': [
      ['claude-sonnet-5', 'Claude Sonnet 5 · balanced (recommended)'],
      ['claude-opus-5', 'Claude Opus 5 · complex work'],
      ['claude-haiku-4-5-20251001', 'Claude Haiku 4.5 · fastest'],
      ['claude-fable-5', 'Claude Fable 5 · highest capability'],
    ],
    'grok-code': [
      ['grok-4.6', 'Grok 4.6 · latest (recommended)'],
      ['grok-4.5', 'Grok 4.5'],
    ],
    codex: [
      ['gpt-5.6-terra', 'GPT-5.6 Terra · balanced (recommended)'],
      ['gpt-5.6-luna', 'GPT-5.6 Luna · fastest'],
      ['gpt-5.6-sol', 'GPT-5.6 Sol · complex work'],
      ['gpt-5.5', 'GPT-5.5'],
      ['gpt-5.4-mini', 'GPT-5.4 Mini'],
    ],
    anthropic: [
      ['claude-sonnet-5', 'Claude Sonnet 5 · balanced (recommended)'],
      ['claude-opus-5', 'Claude Opus 5 · complex work'],
      ['claude-haiku-4-5-20251001', 'Claude Haiku 4.5 · fastest'],
      ['claude-fable-5', 'Claude Fable 5 · highest capability / cost'],
    ],
    openai: [['gpt-5.6', 'GPT-5.6'], ['gpt-5.1', 'GPT-5.1'], ['gpt-5-mini', 'GPT-5 mini'], ['gpt-5-nano', 'GPT-5 nano']],
    xai: [['grok-4.5', 'Grok 4.5'], ['grok-4.3', 'Grok 4.3'], ['grok-build-0.1', 'Grok Build 0.1']],
    ollama: [['llama3.3', 'Llama 3.3'], ['qwen3', 'Qwen 3'], ['gemma3', 'Gemma 3']],
  },
  embedding: { ollama: [['nomic-embed-text', 'nomic-embed-text'], ['mxbai-embed-large', 'mxbai-embed-large'], ['all-minilm', 'all-minilm']] },
  transcription: {
    'whisper-cpp': [['base.en', 'Whisper base.en'], ['small.en', 'Whisper small.en'], ['medium.en', 'Whisper medium.en']],
    openai: [['gpt-4o-transcribe', 'GPT-4o Transcribe'], ['gpt-4o-mini-transcribe', 'GPT-4o mini Transcribe'], ['whisper-1', 'Whisper 1']],
  },
  speech: { openai: [['gpt-4o-mini-tts', 'GPT-4o mini TTS'], ['tts-1', 'TTS-1'], ['tts-1-hd', 'TTS-1 HD']] },
};

export function inferenceDefaultBaseURL(_role, provider) {
  if (provider === 'anthropic') return 'https://api.anthropic.com';
  if (provider === 'xai') return 'https://api.x.ai/v1';
  if (provider === 'openai') return 'https://api.openai.com/v1';
  if (provider === 'ollama') return 'http://localhost:11434';
  return '';
}

export function inferenceProviderLabel(provider) {
  for (const choices of Object.values(inferenceProviders)) {
    const found = choices.find(([value]) => value === provider);
    if (found) return found[1];
  }
  return provider;
}

export function inferenceEndpoint(slot) {
  const configured = ((slot.requires || {}).base_url || '').replace(/\/$/, '');
  if (configured) return configured;
  if (slot.provider === 'claude-code') return 'local Claude Code runtime';
  if (slot.provider === 'codex') return 'local Codex runtime';
  if (slot.provider === 'grok-code') return 'local Grok Build runtime';
  if (slot.provider === 'anthropic') return 'api.anthropic.com';
  if (slot.provider === 'xai') return 'api.x.ai';
  if (slot.provider === 'openai') return 'api.openai.com';
  if (slot.provider === 'ollama') return 'localhost:11434';
  return 'on this device';
}
