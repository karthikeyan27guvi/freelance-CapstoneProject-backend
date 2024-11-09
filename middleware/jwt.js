// import jwt from "jsonwebtoken";
// import createError from "../utils/creatError.js";

// export const verifyToken = (req, res, next)=>{
//     const token = req.cookies.accessToken;
//     if(!token) return next(createError(401,"You are not authenticated"));


//     jwt.verify(token, process.env.JWT_KEY, async (err, payload)=>{
//     if(err) return next(createError(403,"Token is not valid!"));
//         req.userId = payload.id;
//         req.isSeller = payload.isSeller;
//         next()
//       });
// };

import jwt from "jsonwebtoken";
import createError from "../utils/creatError.js";

export const verifyToken = (req, res, next) => {
    // Extract the token from the Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return next(createError(401, "You are not authenticated"));
    }
    
    // Get the token by removing the 'Bearer ' prefix
    const token = authHeader.split(" ")[1];

    jwt.verify(token, process.env.JWT_KEY, (err, payload) => {
        if (err) return next(createError(403, "Token is not valid!"));

        req.userId = payload.id;
        req.isSeller = payload.isSeller;
        next();
    });
};
