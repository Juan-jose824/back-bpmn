/**
 * Script para comprobar que JWT funciona.
 * Ejecutar con: node test-jwt.js
 * Asegúrate de que el servidor esté corriendo (node index.js) en otro terminal.
 */

const BASE = 'http://localhost:3000';

async function request(method, path, body = null, token = null) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    if (token) opts.headers['Authorization'] = 'Bearer ' + token;
    const res = await fetch(BASE + path, opts);
    const text = await res.text();
    let data;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
    return { status: res.status, data };
}

async function main() {
    console.log('=== Prueba JWT ===\n');

    const email = 'test-jwt@test.com';
    const pass = 'test123';

    // 0. Registrar usuario de prueba (si ya existe, no importa)
    console.log('0. Registrar usuario de prueba...');
    await request('POST', '/api/register', { username: 'testjwt', email, password: pass, role: 'user' });
    console.log('   (ignora error si el email ya existe)\n');

    // 1. Login
    console.log('1. Login...');
    const loginRes = await request('POST', '/api/login', { email, pass });
    if (loginRes.status !== 200) {
        console.log('   Falló login:', loginRes.status, loginRes.data);
        console.log('   Usa un usuario que exista en tu BD o revisa que register haya creado test-jwt@test.com.');
        return;
    }
    const accessToken = loginRes.data.accessToken;
    console.log('   OK. accessToken recibido, user:', loginRes.data.user);

    // 2. Ruta protegida CON token
    console.log('\n2. GET /api/users CON token...');
    const withToken = await request('GET', '/api/users', null, accessToken);
    console.log('   Status:', withToken.status, withToken.status === 200 ? 'OK' : withToken.data);

    // 3. Ruta protegida SIN token (debe dar 401)
    console.log('\n3. GET /api/users SIN token (debe dar 401)...');
    const noToken = await request('GET', '/api/users');
    console.log('   Status:', noToken.status, noToken.status === 401 ? 'OK (rechazado como esperado)' : noToken.data);

    // 4. Token inválido (debe dar 403)
    console.log('\n4. GET /api/users con token inventado (debe dar 403)...');
    const badToken = await request('GET', '/api/users', null, 'token-inventado');
    console.log('   Status:', badToken.status, badToken.status === 403 ? 'OK (rechazado como esperado)' : badToken.data);

    console.log('\n=== Si los 4 pasos son correctos, JWT está funcionando. ===');
}

main().catch(err => {
    console.error('Error:', err.message);
    console.error('¿Está el servidor corriendo? (node index.js)');
});
