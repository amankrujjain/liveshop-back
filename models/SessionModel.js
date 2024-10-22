const mongoose = require('mongoose');
const { Schema } = mongoose;

const sessionSchema = new Schema({
  sessionID: { type: String, required: true, unique: true }, // Unique session ID
  data: {
    challenge: { type: String, required: true }, // The WebAuthn challenge
    userID: { type: String, required: true },  // The user ID (base64URL encoded)
    expires: { type: Date, required: true },   // Expiry time for the session
  }
});

// Create a model using the schema
const SessionModel = mongoose.model('Session', sessionSchema);

module.exports = SessionModel;
