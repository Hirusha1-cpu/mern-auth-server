import bcrypt from 'bcryptjs';
import { response } from 'express';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModels.js';
import 'dotenv/config.js';
import transporter from '../config/nodemailer.js';

export const register = async (req, res) => {
    try {
        console.log(req.body);
        
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: "Please fill all the fields" });
        }
        
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new userModel({ name, email, password: hashedPassword });
        await newUser.save();

        const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        // Set cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        // sending mail
        const mailOptions = {
            from: process.env.SENDER_MAIL,
            to: email,
            subject: 'Account Verification',
            text: `Welcome to Finesss! Your account has been created successfully with email: ${email}. `
        }
        await transporter.sendMail(mailOptions);
        return res.status(201).json({ success:true,message: "User registered successfully", token });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Something went wrong" });
    }
};


export const login = async (req, res) => {
    try {
        console.log("req",req.body);
        
        const { email, password } = req.body;
        console.log(email,password);
        
        if (!email || !password) {
            return res.status(400).json({ message: "Please fill all the fields" });
        }
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User does not exist" });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        console.log("JWT_SECRET:", process.env.JWT_SECRET); // Debugging line

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallback_secret", { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({ success:true ,message: "User logged in successfully", token });
    } catch (error) {
        console.error("Login Error:", error);
        return res.status(500).json({ message: `Something went wrong: ${error.message}` });
    }
};

export const logout = async (req, res) => {
    try {
        res.clearCookie('token',{httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', maxAge: 7*24*60*60*1000});
        return res.status(200).json({success:true, message: "User logged out successfully" });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
    }
}


export const senderVerifyOTP = async (req, res) => {
    try {
        // console.log("dsjfnsjifn",req);
        
        const { userId } = req;
        const user = await userModel.findById(userId);
        console.log("hiiiiiii",user);
        
        if (user.isVerified) {
            return res.json({success:false, message: "User is already verified" });
        }
        // 10000 + Math.random * 90000;
        const OTP = String(Math.floor(10000 + Math.random() * 90000));
        user.verifyOTP = OTP;
        user.verifyOTPExpireAt = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_MAIL,
            to: user.email,
            subject: 'Account Verification',
            text: `Your OTP is ${OTP}`
        }
        await transporter.sendMail(mailOptions);
        return res.json({success:true, message: "OTP sent successfully" });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: error.message });
        
    }
}

export const verifyEmail = async (req, res) => {
    console.log("req",req.body);
    
    const { userId} = req;
    const {otp} = req.body;
    if(!userId || !otp){
        return res.status(400).json({message:"Please fill all the fields"});
    }

    try {
        const user = await userModel.findById(userId);
        if(!user){
            return res.status(400).json({message:"User does not exist"});
        }
        if(user.verifyOTP === '' || user.verifyOTP !== otp){
            return res.json({success:false, message: "Invalid OTP" });
        }
        if(user.verifyOTPExpireAt < Date.now()){
            return res.json({success:false, message: "OTP expired" });
        }
        user.isVerified = true;
        user.verifyOTP = '';
        user.verifyOTPExpireAt = 0;

        await user.save();
        return res.json({success:true, message: "Email verified successfully" });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }


}

export const isAuthenticated = async (req, res, next) => {
  try {
    return res.status(200).json({ success: true, message: "User is authenticated" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
}

export const sentResetOtp = async (req, res) => {
    const {email} = req.body;
    if(!email){
        return res.status(400).json({message:"Please fill all the fields"});
    }
    try {
        const user = await userModel.findOne({email});
        if(!user){
            return res.status(400).json({message:"User does not exist"});
        }
        const OTP = String(Math.floor(10000 + Math.random() * 90000));
        user.resetOTP = OTP;
        user.resetOTPExpiresAt = Date.now() + 15 * 60 * 1000;
        await user.save();
        const mailOptions = {
            from: process.env.SENDER_MAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your password reset OTP is ${OTP}`
        }
        await transporter.sendMail(mailOptions);
        return res.json({success:true, message: "OTP sent successfully" });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
}

//reset user password
export const resetPassword = async (req, res) => {
    const {email, otp, newPassword} = req.body;
    if(!email || !otp || !newPassword){
        return res.status(400).json({message:"Please fill all the fields"});
    }
    try {
        const user = await userModel.findOne({email});
        if(!user){
            return res.status(400).json({message:"User does not exist"});
        }

        if(user.resetOTP === '' || user.resetOTP !== otp){
            return res.json({success:false, message: "Invalid OTP" });
        }

        if(user.resetOTPExpiresAt < Date.now()){
            return res.json({success:false, message: "OTP expired" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOTP = '';
        user.resetOTPExpiresAt = 0;
        await user.save();
        return res.json({success:true, message: "Password reset successfully" });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
}