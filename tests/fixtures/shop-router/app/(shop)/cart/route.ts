import { logger } from '../../../lib/logger.js';

export async function POST(request: Request) {
  const item = await request.json();
  logger.warn('cart item', item.id);
  try {
    await fetch('https://payments.example/hold', { method: 'POST' });
  } catch (e) {
  }
  return new Response(null, { status: 201 });
}
