export const products = [
  { id: 1, name: 'The Everyday Tote', category: 'Bags', price: 48, color: 'Natural / 3 colors', tag: 'Bestseller', image: 'photo-1544816155-12df9643f363', description: 'A roomy, sturdy tote for market mornings, library runs, and everything in between.' },
  { id: 2, name: 'Sunday Ceramic Mug', category: 'Home', price: 32, color: 'Warm white', tag: 'Made by hand', image: 'photo-1514228742587-6b1558fcca3d', description: 'A hand-finished ceramic mug with a generous handle and a shape that feels just right.' },
  { id: 3, name: 'Cloud Knit Sweater', category: 'Clothing', price: 96, color: 'Oatmeal / 2 colors', tag: '', image: 'photo-1576566588028-4147f3842f27', description: 'A soft, easygoing knit made for cool mornings and slow evenings.' },
  { id: 4, name: 'Sculpted Catchall', category: 'Home', price: 38, color: 'Sandstone', tag: 'Small batch', image: 'photo-1610701596007-11502861dcfa', description: 'A small-batch catchall for the everyday things that deserve a place of their own.' },
  { id: 5, name: 'Weekend Canvas Pack', category: 'Bags', price: 72, color: 'Olive / 2 colors', tag: '', image: 'photo-1553062407-98eeb64c6a62', description: 'A dependable canvas pack with room for a change of plans and a little extra.' },
  { id: 6, name: 'Ribbed Lounge Set', category: 'Clothing', price: 84, color: 'Cocoa', tag: 'Almost gone', image: 'photo-1551488831-00ddcb6c6bd3', description: 'An easy ribbed set designed for a softer start and a slower finish to the day.' },
  { id: 7, name: 'Soft Form Vase', category: 'Home', price: 56, color: 'Chalk', tag: '', image: 'photo-1578500494198-246f612d3b3d', description: 'A quiet, sculptural vase that looks lovely with fresh stems or all on its own.' },
  { id: 8, name: 'Daily Carry Pouch', category: 'Bags', price: 29, color: 'Ink / 4 colors', tag: '', image: 'photo-1622560480654-d96214fdc887', description: 'A small, useful pouch to keep the little essentials close at hand.' },
]

export const categories = ['Everything', 'Clothing', 'Bags', 'Home']

export function mapProductRecord(product) {
  return {
    id: product.id,
    name: product.name,
    category: product.category,
    price: product.price_cents / 100,
    color: product.color,
    tag: product.tag,
    image: product.image,
    description: product.description,
    isActive: product.is_active,
  }
}

export function imageUrl(image, width = 720) {
  return `https://images.unsplash.com/${image}?auto=format&fit=crop&w=${width}&q=85`
}

export function formatPrice(amount) {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount)
}
