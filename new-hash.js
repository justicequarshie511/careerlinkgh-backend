const bcrypt = require('bcryptjs');

// Generate hash for admin123
bcrypt.hash('admin123', 10, (err, hash) => {
    if (err) throw err;
    console.log('========================================');
    console.log('NEW HASH FOR admin123:');
    console.log(hash);
    console.log('========================================');
    console.log('\nCopy this hash and run this SQL:');
    console.log(`UPDATE users SET password_hash = '${hash}' WHERE email = 'admin@careerlinkgh.com';`);
    console.log('\nOr create new admin:');
    console.log(`INSERT INTO users (id, email, password_hash, first_name, last_name, user_type, email_verified, is_active) VALUES (UUID(), 'admin@careerlinkgh.com', '${hash}', 'Admin', 'User', 'admin', 1, 1);`);
});