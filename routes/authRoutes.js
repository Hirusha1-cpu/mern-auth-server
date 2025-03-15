import express from 'express';
import { isAuthenticated, login, logout, register, resetPassword, senderVerifyOTP, sentResetOtp, verifyEmail } from '../controllers/authController.js';
import userAuth from '../middleware/userAuth.js';

const authRouter = express.Router();

authRouter.post('/register',register); 
authRouter.post('/login',login);
authRouter.post('/logout',logout);
authRouter.post('/send-verify-otp',userAuth, senderVerifyOTP);
authRouter.post('/verify-account',userAuth, verifyEmail);
authRouter.get('/isauth',userAuth, isAuthenticated);
authRouter.post('/sent-reset-otp',sentResetOtp);
authRouter.post('/reset-password',resetPassword);

export default authRouter;
