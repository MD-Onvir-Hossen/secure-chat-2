// Firefly effect for Secure Chat logo
// Adds yellow glowing dots that move around the logo area

document.addEventListener('DOMContentLoaded', function () {
  const logoRow = document.querySelector('.logo-title-row');
  if (!logoRow) return;

  // Create a container for fireflies
  const fireflyContainer = document.createElement('div');
  fireflyContainer.className = 'firefly-container';
  fireflyContainer.style.position = 'absolute';
  fireflyContainer.style.left = 0;
  fireflyContainer.style.top = 0;
  fireflyContainer.style.width = '100%';
  fireflyContainer.style.height = '100%';
  fireflyContainer.style.pointerEvents = 'none';
  fireflyContainer.style.zIndex = 10;
  logoRow.style.position = 'relative';
  logoRow.appendChild(fireflyContainer);

  // Create fireflies
  const FIREFLY_COUNT = 7;
  for (let i = 0; i < FIREFLY_COUNT; i++) {
    const firefly = document.createElement('div');
    firefly.className = 'firefly';
    fireflyContainer.appendChild(firefly);
    animateFirefly(firefly, logoRow.offsetWidth, logoRow.offsetHeight);
  }

  function animateFirefly(firefly, width, height) {
    function move() {
      const x = Math.random() * (width - 20);
      const y = Math.random() * (height - 20);
      const duration = 2 + Math.random() * 3;
      firefly.style.transition = `transform ${duration}s linear`;
      firefly.style.transform = `translate(${x}px, ${y}px)`;
      setTimeout(move, duration * 1000);
    }
    move();
  }
});
