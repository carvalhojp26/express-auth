require('dotenv').config()
const mongoose = require('mongoose');

async function connectDB() {
    try {
        await mongoose.connect("mongodb://localhost:27017/auth") // Adicionar .env
        console.log("connected to database")
    } catch (error) {
        console.error(error)
        process.exit(1)
    }
}

module.exports = connectDB