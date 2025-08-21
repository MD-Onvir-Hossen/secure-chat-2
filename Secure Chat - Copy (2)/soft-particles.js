// Soft, blurred floating particles for background
// Particles will stay behind the logo area

document.addEventListener('DOMContentLoaded', function () {
  const colors = ['#ffd70044', '#43cea244', '#764ba244', '#23252633'];
  const count = 18;
  const container = document.createElement('div');
  container.className = 'soft-particles-bg';
  container.style.position = 'fixed';
  container.style.left = 0;
  container.style.top = 0;
  container.style.width = '100vw';
  container.style.height = '100vh';
  container.style.zIndex = '-1';
  container.style.pointerEvents = 'none';
  document.body.prepend(container);

  // Get logo position and size
  function getLogoRect() {
    const logo = document.querySelector('.main-logo-img');
    if (!logo) return null;
    return logo.getBoundingClientRect();
  }

  for (let i = 0; i < count; i++) {
    const p = document.createElement('div');
    p.className = 'soft-particle';
    const size = 60 + Math.random() * 80;
    p.style.width = p.style.height = size + 'px';
    p.style.background = colors[Math.floor(Math.random() * colors.length)];
    p.style.opacity = 0.18 + Math.random() * 0.13;
    p.style.filter = 'blur(8px)';
    p.style.position = 'absolute';
    p.style.borderRadius = '50%';
    p.style.transition = 'all 16s linear';
    container.appendChild(p);
    animate(p);
  }

  function animate(p) {
    function moveParticle() {
      let tries = 0;
      let x, y, logoRect;
      do {
        x = Math.random() * window.innerWidth;
        y = Math.random() * window.innerHeight;
        logoRect = getLogoRect();
        tries++;
      } while (
        logoRect &&
        x + 40 > logoRect.left &&
        x < logoRect.right + 40 &&
        y + 40 > logoRect.top &&
        y < logoRect.bottom + 40 &&
        tries < 10
      );
      p.style.left = x + 'px';
      p.style.top = y + 'px';
      setTimeout(moveParticle, 12000 + Math.random() * 6000);
    }
    moveParticle();
  }
});
