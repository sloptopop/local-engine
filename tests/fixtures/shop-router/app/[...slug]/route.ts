import { db } from '../../lib/db.js';

export async function GET(request: Request) {
  const slug = new URL(request.url).pathname;
  const { data: page } = await db.from('pages').select('*').eq('slug', slug).single();
  const { data: moved } = await db.from('redirects').select('target').eq('slug', slug).maybeSingle();
  return Response.json({ page, moved });
}
