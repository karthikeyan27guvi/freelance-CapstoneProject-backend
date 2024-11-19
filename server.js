import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import userRoute from "./routes/user.route.js";
import authRoute from "./routes/auth.route.js";
import conversationRoute from "./routes/conversation.route.js";
import gigRoute from "./routes/gig.route.js";
import messageRoute from "./routes/message.route.js";
import reviewRoute from "./routes/review.route.js";
import orderRoute from "./routes/order.route.js";
import cors from "cors";


const app = express()
dotenv.config();

const connet = async ()=>{

    try {
        await mongoose.connect(process.env.MONGO);
        console.log("connected to mongoDB")
    } catch (error) {
        console.log(error);
    }
}

app.use(cors({
    origin: 'https://freelancerjobportal.netlify.app',
    credentials: true, 
    methods: "GET,POST,PUT,DELETE", 
    allowedHeaders: ['Authorization', 'Content-Type']
}));

// Allow preflight requests for all routes
app.options("*", cors());
// Middleware
app.use(express.json())


app.use("/api/auth", authRoute)
app.use("/api/users", userRoute)
app.use("/api/conversations", conversationRoute)
app.use("/api/gigs", gigRoute)
app.use("/api/messages", messageRoute)
app.use("/api/reviews", reviewRoute)
app.use("/api/orders", orderRoute)

app.use((err,req,res,next)=>{
    const errorStatus = err.status ||500
    const errorMessage = err.message || 'Something went wrong!'

    return res.status(errorStatus).send(errorMessage);
})

app.listen(8800,()=>{
    connet();
    console.log('server is running on port 8800')
})
