import { db } from '../../../lib/db.js';

export async function GET(request: Request) {
  const id = new URL(request.url).pathname.split('/').pop() ?? '';
  const { data } = await db.from('orders').select('*').eq('id', id);
  return Response.json(data);
}

export async function PATCH(request: Request) {
  const order = await request.json();
  await db.from('orders').update(order).eq('id', order.id);
  return new Response(null, { status: 204 });
}

export async function HEAD(request: Request) {
  const id = new URL(request.url).pathname.split('/').pop() ?? '';
  const { data: items, error } = await db.from('order_items').select('id').eq('order_id', id);
  return new Response(null, { status: items?.length ? 200 : 404 });
}
