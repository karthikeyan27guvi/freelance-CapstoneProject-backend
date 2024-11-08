import User from '../models/user.model.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import createError from '../utils/creatError.js';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

export const register = async (req, res, next)=>{

    try {
        const hash = bcrypt.hashSync(req.body.password, 5)
        const newUser = new User({
            ...req.body,
            password: hash,
        })
        await newUser.save();
        res.status(201).send("User has been created successfully");
    } catch (err) {
        next(err);
    }
}


export const login = async (req, res, next)=>{

    try {
        const user = await User.findOne({username: req.body.username});
        if(!user) return next(createError(404, "User not found!"));

        const isCorrect = bcrypt.compareSync(req.body.password, user.password);
        if(!isCorrect) 
            return next(createError(400, "Wrong password or username"));

        const token = jwt.sign({
            id: user._id, 
            isSeller: user.isSeller,
        },process.env.JWT_KEY
        );

        const {password, ...info} = user._doc
        res
        .cookie("accessToken", token,{
            httpOnly: true,
        })
        .status(200)
        .send(info)

    } catch (err) {
        next(err)
    }
}


export const logout = async (req,res)=>{
    res.clearCookie("accessToken",{
        sameSite: "none",
        secure: true,
    })
    .status(200)
    .send("User has been logged out.");
}

export const forgotPassword = async (req, res, next) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) return next(createError(404, "User not found!"));

        // Generate a reset token
        const resetToken = crypto.randomBytes(32).toString("hex");

        // Store hashed token and expiry on user
        user.resetPasswordToken = crypto.createHash("sha256").update(resetToken).digest("hex");
        user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes expiry

        await user.save();

        // Construct password reset URL
        const resetUrl = `https://freelancerjobportal.netlify.app/reset-password/${resetToken}`;


        // Send email with reset link
        const transporter = nodemailer.createTransport({
            service: 'gmail', // You can use any email service here
            auth: {
                user: process.env.EMAIL_USERNAME,
                pass: process.env.EMAIL_PASSWORD,
            }
        });

        const mailOptions = {
            from: process.env.EMAIL_USERNAME,
            to: user.email,
            subject: "Password Reset Request",
            text: `You are receiving this email because you (or someone else) have requested to reset the password for your account. Please click the link below to reset your password: \n\n ${resetUrl}`
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: "Reset link has been sent to your email." });
    } catch (err) {
        next(err);
    }
};

// Reset Password Function
export const resetPassword = async (req, res, next) => {
    try {
        // Hash the token sent in the URL to match the stored hash
        const resetPasswordToken = crypto.createHash("sha256").update(req.params.token).digest("hex");

        // Find user by the token and check if it's still valid
        const user = await User.findOne({
            resetPasswordToken,
            resetPasswordExpire: { $gt: Date.now() },
        });

        if (!user) return next(createError(400, "Invalid or expired token"));

        // Hash the new password and save it
        const hash = bcrypt.hashSync(req.body.password, 5);
        user.password = hash;

        // Clear the reset token fields
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;

        await user.save();

        res.status(200).json({ message: "Password has been reset successfully." });
    } catch (err) {
        next(err);
    }
};