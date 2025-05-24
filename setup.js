
const fs = require('fs');
const { execSync } = require('child_process');
const path = require('path');

console.log('🚀 অটোমেটিক সেটআপ শুরু হচ্ছে...');

// Required packages with versions
const requiredPackages = {
  'express': '^4.18.2',
  'body-parser': '^1.20.2',
  'dotenv': '^16.0.3',
  'express-rate-limit': '^6.7.0',
  'socket.io': '^4.6.1',
  'twilio': '^4.10.0'
};

try {
  // Create necessary directories
  const dirs = ['public'];
  dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
      console.log(`📁 ${dir} ফোল্ডার তৈরি হচ্ছে...`);
      fs.mkdirSync(dir);
    }
  });

  // Create or update package.json
  console.log('📦 package.json আপডেট হচ্ছে...');
  const packageJson = {
    name: 'twilio-sms-app',
    version: '1.0.0',
    main: 'index.js',
    scripts: {
      start: 'node index.js',
      setup: 'node setup.js'
    },
    dependencies: requiredPackages
  };
  fs.writeFileSync('package.json', JSON.stringify(packageJson, null, 2));

  // Create .env if not exists
  if (!fs.existsSync('.env')) {
    console.log('🔑 .env ফাইল তৈরি হচ্ছে...');
    fs.writeFileSync('.env', 'PORT=5000\n');
  }

  // Install dependencies
  console.log('📦 প্যাকেজ ইনস্টল হচ্ছে...');
  execSync('npm install', {stdio: 'inherit'});

  console.log('\n✅ সেটআপ সম্পন্ন হয়েছে!');
  console.log('\n🎉 এখন আপনি নিম্নলিখিত কমান্ড দিয়ে সার্ভার চালু করতে পারেন:');
  console.log('npm start');

} catch (error) {
  console.error('❌ সেটআপে সমস্যা হয়েছে:', error.message);
}
