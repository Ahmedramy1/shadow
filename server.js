const path = require('path');
require('./core').start(process.env.PORT || 8787, path.join(__dirname, 'index.html'));
console.log('Shadow cloud server running');
