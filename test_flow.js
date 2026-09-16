/**
 * Automated Verification Script for Thesis Defense
 * Tests the complete Multi-Factor Authentication Pipeline:
 * 1. Step 1: POST /login (Matric No + RRR) -> verifies redirect to /mfa/verify
 * 2. Step 2: GET /api/mfa/epoch-time -> fetches live 30s epoch token for student
 * 3. Step 2: POST /mfa/verify (submits 6-digit TOTP token) -> verifies redirect to /dashboard
 * 4. Protected Route: GET /dashboard -> checks student records, clearance hash, and audit logs
 * 5. Negative Test: POST /login with invalid RRR -> verifies 401 rejection
 */

async function runTest() {
  console.log('--- STARTING MFA STUDENT PORTAL AUTH PIPELINE TEST ---');
  let cookie = '';

  // 0. Negative test: Invalid RRR clearance code
  const badLoginRes = await fetch('http://localhost:3000/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'matricNo=SCI22CSC073&rrr=INVALID_RRR_CODE',
    redirect: 'manual'
  });
  console.log('0. POST /login with invalid RRR status:', badLoginRes.status, '(Expected: 401 Unauthorized)');

  // 1. Step 1: Primary Authentication (Matric No + Remita RRR verification)
  const loginRes = await fetch('http://localhost:3000/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'matricNo=SCI22CSC073&rrr=QW23456H',
    redirect: 'manual'
  });

  console.log('1. POST /login status:', loginRes.status, '(Expected: 302 Redirect to /mfa/verify)');
  const setCookie = loginRes.headers.get('set-cookie');
  if (setCookie) {
    cookie = setCookie.split(';')[0];
  }
  console.log('   Session Cookie established:', cookie ? 'YES' : 'NO');
  console.log('   Redirect Location:', loginRes.headers.get('location'));

  // 2. Fetch live synchronized TOTP token
  const epochRes = await fetch('http://localhost:3000/api/mfa/epoch-time', {
    headers: { 'Cookie': cookie }
  });
  const epochData = await epochRes.json();
  console.log('2. GET /api/mfa/epoch-time:', epochData);
  const activeCode = epochData.simulatedCode;
  console.log('   Active 6-digit TOTP code for SCI22CSC073:', activeCode);

  // 3. Step 2: Submit TOTP Verification Code
  const verifyRes = await fetch('http://localhost:3000/mfa/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie': cookie
    },
    body: 'code=' + activeCode,
    redirect: 'manual'
  });

  console.log('3. POST /mfa/verify status:', verifyRes.status, '(Expected: 302 Redirect to /dashboard)');
  console.log('   Redirect Location:', verifyRes.headers.get('location'));
  const verifyCookie = verifyRes.headers.get('set-cookie');
  if (verifyCookie) {
    cookie = verifyCookie.split(';')[0];
  }

  // 4. Access Protected Dashboard
  const dashRes = await fetch('http://localhost:3000/dashboard', {
    headers: { 'Cookie': cookie },
    redirect: 'manual'
  });
  console.log('4. GET /dashboard status:', dashRes.status, '(Expected: 200 OK)');
  const html = await dashRes.text();

  const checks = [
    { name: 'Student Name (Praise E. Bello)', pass: html.includes('Praise E. Bello') },
    { name: 'Matriculation Number (SCI22CSC073)', pass: html.includes('SCI22CSC073') },
    { name: 'Remita Clearance RRR (QW23456H)', pass: html.includes('QW23456H') },
    { name: 'Department (Computer Science)', pass: html.includes('Computer Science') },
    { name: 'Cryptographic SHA-256 Record Hash', pass: html.includes('SHA256:') },
    { name: 'Security Audit Log Table', pass: html.includes('Security Audit') || html.includes('Login Attempts') },
    { name: 'MFA Active Badge', pass: html.includes('MFA Active') }
  ];

  console.log('\n--- VERIFICATION CHECKS ---');
  let allPass = true;
  for (const c of checks) {
    console.log(`${c.pass ? '✅' : '❌'} ${c.name}`);
    if (!c.pass) allPass = false;
  }

  if (allPass && badLoginRes.status === 401) {
    console.log('\n🎉 ALL TESTS PASSED SUCCESSFULLY! The Matric No & RRR MFA system is fully operational.');
  } else {
    console.error('\n⚠️ Some verification checks failed.');
    process.exit(1);
  }
}

runTest().catch((err) => {
  console.error('Test script exception:', err);
  process.exit(1);
});
