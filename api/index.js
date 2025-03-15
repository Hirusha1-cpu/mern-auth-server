import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import connectDB from '../config/mongodb.js';
import authRouter from '../routes/authRoutes.js';
import userRouter from '../routes/userRoutes.js';

const app = express();
const port = process.env.PORT || 4000;

// Connect to MongoDB
connectDB();

// Middleware
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// Root route
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the MERN Auth Server' });
});

// API routes
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

// Test route
app.get('/api/test', (req, res) => {
  res.json({ message: 'Server is running' });
});

// Debug route
app.get('/api/debug', (req, res) => {
  res.json({
    message: 'Server is running',
    env: process.env.NODE_ENV,
    cors: {
      allowedOrigins: [
        'http://localhost:5173',
        'https://mern-auth-client-omega.vercel.app/',
        'https://mern-auth-drab-two.vercel.app',
        'https://mern-auth-client-81ifaaheb-hirushafernando121gmailcoms-projects.vercel.app'
      ]
    }
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

export default app;
