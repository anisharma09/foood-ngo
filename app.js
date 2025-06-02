import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import path from "path";
import useRouter from "./routes/userRouter.js";
import adminRouter from "./routes/adminRouter.js";
import agentRouter from "./routes/agentRouter.js";
import donerRouter from "./routes/donerRouter.js";
import dbConnection from "./database/dbconnection.js";
import ErrorHandler from "./middlewares/error.js";
import errorMiddleware from "./middlewares/error.js";
import { fileURLToPath } from 'url';
const PORT = process.env.PORT || 4000;
const app = express();
dotenv.config({ path: "./config/config.env " });
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pagesPath = path.join(__dirname, 'pages');
app.use(express.static(pagesPath));

app.get("/", (req, res) => {
  // res.send("Hello World");
  res.sendFile(path.join(pagesPath, 'WelcomePage.html'));
});
 
app.use(
  cors({
    origin: 'http://localhost:5173',  
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true, // Allow credentials
  })
);
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/api/v1/user", useRouter); 
app.use("/api/v1/admin", adminRouter);
app.use("/api/v1/agent", agentRouter);
app.use("/api/v1/doner", donerRouter);

dbConnection();
app.use(ErrorHandler);
app.use(errorMiddleware);

export default app;

