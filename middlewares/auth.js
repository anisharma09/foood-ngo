import jwt from 'jsonwebtoken';
import User from '../models/userSchema.js';
import ErrorHandler from './error.js';
import { catchASyncError } from './catchASyncError.js';

export const isAuthorized = catchASyncError(async (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return next(new ErrorHandler('Please provide a valid token', 401));
    }

    const token = authHeader.split(' ')[1];
    
    if (!token) {
        return next(new ErrorHandler('Token not found', 401));
    }

    try {
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
        
        if (!decodedToken) {
            return next(new ErrorHandler('Invalid token', 401));
        }

        const user = await User.findById(decodedToken.id);
        
        if (!user) {
            return next(new ErrorHandler('User not found', 404));
        }

        req.user = user;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return next(new ErrorHandler('Token has expired', 401));
        }
        return next(new ErrorHandler('Invalid token', 401));
    }
});
