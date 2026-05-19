const fs = require('fs');
const html = fs.readFileSync('dashboard.html', 'utf8');
console.log("Script block count:", (html.match(/<script>/g) || []).length);
