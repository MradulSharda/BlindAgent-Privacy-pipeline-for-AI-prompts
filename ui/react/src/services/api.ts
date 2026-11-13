export interface ServerStatus {
  status: string;
  engine: string;
  default_k: number;
  default_n: number;
  provider: 'gemini' | 'openai' | 'simulator' | string;
  active_model?: string;
  has_gemini_key?: boolean;
}

export interface VaultEntity {
  token: string;
  entity_type: string;
  original_value: string;
  ciphertext_hex?: string;
  alpha?: number;
  beta?: number;
  shares: string[];
}

export interface PipelineMetrics {
  entities_protected: number;
  blinded_entropy_bits: number;
  characters_shielded?: number;
}

export interface ExecuteResponse {
  user_input: string;
  wire_payload: string;
  host_raw_response: string;
  final_output: string;
  execution_time_ms: number;
  metrics: PipelineMetrics;
  provider: string;
  active_model?: string;
  last_error?: string | null;
  vault: VaultEntity[];
}

export interface SSSSplitResponse {
  k: number;
  n: number;
  shares: string[];
}

export interface SSSCombineResponse {
  recovered?: string;
  detail?: string;
}

const BASE_URL = '';

export async function fetchServerStatus(): Promise<ServerStatus> {
  const res = await fetch(`${BASE_URL}/api/status`);
  if (!res.ok) throw new Error('Failed to fetch server status');
  return res.json();
}

export async function executePipeline(
  prompt: string,
  threshold: number = 3,
  totalShares: number = 5,
  systemPrompt?: string
): Promise<ExecuteResponse> {
  const res = await fetch(`${BASE_URL}/api/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      prompt,
      system_prompt: systemPrompt,
      threshold,
      total_shares: totalShares,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Execution failed' }));
    throw new Error(err.detail || 'Execution failed');
  }
  return res.json();
}

export async function splitSecret(secret: string, k: number = 3, n: number = 5): Promise<SSSSplitResponse> {
  const res = await fetch(`${BASE_URL}/api/sss/split`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secret, k, n }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Split failed' }));
    throw new Error(err.detail || 'Split failed');
  }
  return res.json();
}

export async function combineShares(shares: string[], k: number = 3): Promise<SSSCombineResponse> {
  const res = await fetch(`${BASE_URL}/api/sss/combine`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ shares, k }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Reconstruction failed' }));
    throw new Error(err.detail || 'Reconstruction failed');
  }
  return res.json();
}
