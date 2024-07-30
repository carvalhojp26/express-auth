const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    userId: {
        type: Number,
        required: true
    },
    username: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true
    }
})

module.exports = mongoose.model('User', UserSchema)