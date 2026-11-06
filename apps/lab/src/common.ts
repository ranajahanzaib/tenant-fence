export type Identity = { tenant_id: string };
export type Document = {
  id: string;
  tenant_id: string;
  title: string;
  content: string;
};
export function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}
export async function authenticate(
  request: Request,
  env: Env,
): Promise<Identity | null> {
  const auth = request.headers.get("Authorization");
  if (!auth?.startsWith("Bearer ") || auth.length > 4096) return null;
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(auth.slice(7)),
  );
  const hex = Array.from(new Uint8Array(hash), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
  return env.DB.prepare(
    "SELECT u.tenant_id FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=?1",
  )
    .bind(hex)
    .first<Identity>();
}
export async function titleInput(request: Request): Promise<string | null> {
  if (!request.headers.get("Content-Type")?.startsWith("application/json"))
    return null;
  if (Number(request.headers.get("Content-Length")) > 4096) return null;
  const reader = request.body?.getReader();
  if (!reader) return null;
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 4096) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    const data: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (
      typeof data !== "object" ||
      data === null ||
      !("title" in data) ||
      Object.keys(data).some((k) => k !== "title")
    )
      return null;
    return typeof data.title === "string" &&
      data.title.length > 0 &&
      data.title.length <= 200
      ? data.title
      : null;
  } catch {
    return null;
  }
}
