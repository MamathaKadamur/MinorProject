const mongoose = require('mongoose');

const db = async () => {
    try {
        console.log('Attempting to connect to MongoDB...'); // Debug log
        console.log('MongoDB URL:', process.env.MONGO_URL ? 'URL is set' : 'URL is not set'); // Debug log (without exposing the actual URL)
        
        mongoose.set('strictQuery', false);
        const options = {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        };
        
        await mongoose.connect(process.env.MONGO_URL, options);
        console.log('MongoDB Connected Successfully');
        
        // Log connection state
        console.log('MongoDB Connection State:', mongoose.connection.readyState);
        // 0 = disconnected
        // 1 = connected
        // 2 = connecting
        // 3 = disconnecting
    } catch (error) {
        console.error('MongoDB Connection Error Details:', {
            name: error.name,
            message: error.message,
            code: error.code,
            stack: error.stack
        });
        process.exit(1);
    }
}

module.exports = {db}