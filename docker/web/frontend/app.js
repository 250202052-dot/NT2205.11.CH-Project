'use strict';
const money = value => new Intl.NumberFormat('vi-VN', {style: 'currency', currency: 'VND'}).format(value);
const escapeHtml = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
let products = [], category = 'Tất cả', busy = false, requestId = null, toastTimer;
let cart = {};
try {
  const saved = JSON.parse(localStorage.getItem('nook-cart') || '{}');
  if (saved && typeof saved === 'object' && !Array.isArray(saved)) {
    for (const [id, quantity] of Object.entries(saved)) {
      if (/^\d+$/.test(id) && Number.isInteger(quantity) && quantity > 0 && quantity <= 10) cart[id] = quantity;
    }
  }
} catch (_) { /* Cart still works when browser storage is unavailable. */ }
const dialog = document.querySelector('#cart-dialog');
const illustration = product => `<div class="illustration ${escapeHtml(product.illustration)}" aria-hidden="true"></div>`;
function persist() {
  try { localStorage.setItem('nook-cart', JSON.stringify(cart)); } catch (_) {}
  document.querySelector('#cart-count').textContent = Object.values(cart).reduce((a, b) => a + b, 0);
}
function toast(message) {
  const element = document.querySelector('#toast');
  element.textContent = message; element.classList.add('visible');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => element.classList.remove('visible'), 2600);
}
async function api(path, options) {
  const response = await fetch(path, {...options, signal: AbortSignal.timeout(12000)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Không thể hoàn tất yêu cầu.');
  return result;
}
function renderProducts() {
  const search = document.querySelector('#search').value.trim().toLocaleLowerCase('vi');
  const filtered = products.filter(p => (category === 'Tất cả' || p.category === category) && `${p.name} ${p.description}`.toLocaleLowerCase('vi').includes(search));
  document.querySelector('#product-count').textContent = `${filtered.length} sản phẩm được chọn lọc`;
  document.querySelector('#catalog-message').textContent = filtered.length ? '' : 'Chưa tìm thấy sản phẩm. Thử từ khóa hoặc danh mục khác nhé.';
  document.querySelector('#products').innerHTML = filtered.map(p => `<article class="product-card">
    <div class="product-image ${escapeHtml(p.color)}">${p.badge ? `<span class="badge">${escapeHtml(p.badge)}</span>` : ''}${illustration(p)}</div>
    <p class="product-type">${escapeHtml(p.category)}</p><h3>${escapeHtml(p.name)}</h3>
    <p class="product-description">${escapeHtml(p.description)}</p><div class="product-bottom"><span class="product-price">${money(p.price)}</span>
    <button class="add-button" data-add="${p.id}" aria-label="Thêm ${escapeHtml(p.name)} vào giỏ" ${p.stock === 0 ? 'disabled' : ''}>${p.stock === 0 ? '×' : '+'}</button></div></article>`).join('');
}
async function loadProducts() {
  const result = await api('/api/products'); products = result.products;
  const categories = ['Tất cả', ...new Set(products.map(p => p.category))];
  document.querySelector('#categories').innerHTML = categories.map(name => `<button class="category ${name === category ? 'active' : ''}" data-category="${escapeHtml(name)}" aria-pressed="${name === category}">${escapeHtml(name)}</button>`).join('');
  for (const id of Object.keys(cart)) if (!products.some(p => p.id === Number(id))) delete cart[id];
  persist(); renderProducts(); document.querySelector('#products').setAttribute('aria-busy', 'false');
}
function renderCart() {
  const selected = products.filter(p => cart[p.id]);
  document.querySelector('#order-success').hidden = true;
  document.querySelector('#cart-bottom').hidden = !selected.length;
  document.querySelector('#cart-items').innerHTML = selected.length ? selected.map(p => `<div class="cart-item">
    <div class="cart-thumbnail ${escapeHtml(p.color)}">${illustration(p)}</div><div><h3>${escapeHtml(p.name)}</h3>
    <span class="cart-item-price">${money(p.price)}</span><div class="cart-item-controls"><div class="quantity">
    <button data-decrease="${p.id}" aria-label="Giảm số lượng ${escapeHtml(p.name)}" ${busy ? 'disabled' : ''}>−</button><span>${cart[p.id]}</span>
    <button data-increase="${p.id}" aria-label="Tăng số lượng ${escapeHtml(p.name)}" ${busy || cart[p.id] >= Math.min(10,p.stock) ? 'disabled' : ''}>+</button></div>
    <button class="remove" data-remove="${p.id}" ${busy ? 'disabled' : ''}>Bỏ khỏi giỏ</button></div></div></div>`).join('') : '<div class="empty-cart"><strong>Góc nhỏ đang chờ bạn.</strong>Thêm một món đồ yêu thích vào giỏ để bắt đầu.</div>';
  document.querySelector('#subtotal').textContent = money(selected.reduce((sum, p) => sum + p.price * cart[p.id], 0));
  document.querySelector('#checkout').disabled = busy || !selected.length;
  document.querySelector('#checkout').textContent = busy ? 'Đang xác nhận đơn hàng…' : 'Đặt hàng thử nghiệm →';
}
function updateCart(id, quantity) {
  if (busy) return;
  const product = products.find(p => p.id === Number(id));
  if (!product) return;
  if (quantity > Math.min(10, product.stock)) { toast('Đã đạt số lượng tối đa hoặc hết hàng.'); return; }
  if (quantity <= 0) delete cart[id]; else cart[id] = quantity;
  requestId = null; document.querySelector('#checkout-error').textContent = '';
  persist(); if (dialog.open) renderCart();
}
document.querySelector('#products').addEventListener('click', event => {
  const button = event.target.closest('[data-add]'); if (!button || busy) return;
  const id = button.dataset.add, before = cart[id] || 0;
  updateCart(id, before + 1); if (cart[id] > before) toast('Đã thêm vào giỏ hàng.');
});
document.querySelector('#categories').addEventListener('click', event => {
  const button = event.target.closest('[data-category]'); if (!button) return;
  category = button.dataset.category;
  for (const item of document.querySelectorAll('[data-category]')) {
    const active = item === button; item.classList.toggle('active', active); item.setAttribute('aria-pressed', String(active));
  }
  renderProducts();
});
document.querySelector('#search').addEventListener('input', renderProducts);
document.querySelector('#open-cart').addEventListener('click', () => { renderCart(); if (!dialog.open) dialog.showModal(); });
document.querySelector('#close-cart').addEventListener('click', () => { if (!busy) dialog.close(); });
dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
document.querySelector('#cart-items').addEventListener('click', event => {
  const button = event.target.closest('button'); if (!button) return;
  if (button.dataset.increase) updateCart(button.dataset.increase, cart[button.dataset.increase] + 1);
  if (button.dataset.decrease) updateCart(button.dataset.decrease, cart[button.dataset.decrease] - 1);
  if (button.dataset.remove) updateCart(button.dataset.remove, 0);
});
document.querySelector('#checkout').addEventListener('click', async () => {
  if (busy || !Object.keys(cart).length) return;
  busy = true; requestId ||= crypto.randomUUID(); renderCart();
  document.querySelector('#checkout-error').textContent = '';
  try {
    const order = await api('/api/orders', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({request_id: requestId, items: Object.entries(cart).map(([id, quantity]) => ({product_id: Number(id), quantity}))})});
    cart = {}; requestId = null; persist();
    document.querySelector('#cart-items').innerHTML = ''; document.querySelector('#cart-bottom').hidden = true;
    const success = document.querySelector('#order-success'); success.hidden = false;
    success.innerHTML = `<div class="check">✓</div><h3>Đơn hàng đã được ghi nhận!</h3><p>Cảm ơn bạn đã ghé Nook.<br>Đây là đơn thử nghiệm, không phát sinh thanh toán.</p><p>Mã đơn hàng<br><code>${escapeHtml(order.id)}</code></p><p>Tổng cộng: <strong>${money(order.total)}</strong></p><button id="continue-shopping">Tiếp tục khám phá ↗</button>`;
    document.querySelector('#continue-shopping').addEventListener('click', () => dialog.close());
    try { await loadProducts(); } catch (_) { toast('Đơn đã lưu; tải lại trang để cập nhật tồn kho.'); }
  } catch (error) {
    document.querySelector('#checkout-error').textContent = error.name === 'TimeoutError' ? 'Kết nối chậm. Bấm thử lại để xác nhận cùng đơn hàng.' : error.message;
  } finally {
    busy = false; if (document.querySelector('#order-success').hidden) renderCart();
  }
});
persist();
loadProducts().catch(() => {
  document.querySelector('#products').setAttribute('aria-busy', 'false');
  document.querySelector('#product-count').textContent = 'Chưa tải được sản phẩm';
  document.querySelector('#catalog-message').textContent = 'Cửa hàng chưa kết nối được máy chủ. Vui lòng tải lại trang sau ít phút.';
});
