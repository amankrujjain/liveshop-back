require('dotenv').config();

console.log("Admin salt key", process.env.ADMINSAULTKEY)
console.log("User salt key", process.env.USERSAULTKEY)

function generateSecretKey(role) {
    if (role === 'Admin') {
      if (!process.env.ADMINSAULTKEY) {
        throw new Error('ADMINSALTKEY is not set');
      }
      return process.env.ADMINSAULTKEY;
    } else {
      if (!process.env.USERSAULTKEY) {
        throw new Error('USERSALTKEY is not set');
      }
      return process.env.USERSAULTKEY;
    }
  }
  
  module.exports = generateSecretKey;
