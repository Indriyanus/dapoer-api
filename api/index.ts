import express, { Application, Request, Response, NextFunction } from "express";
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import router from "./routers";
import dotenv from 'dotenv';

const path = require('path');

const app: Application = express();
const port: number = 2024;
// Load environment variables from .env file
dotenv.config();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, '../public/uploads'))); // Pastikan jalur file statis benar

app.use(router);

app.get("/", (req: Request, res: Response) => {
    res.send({
        hello: "PT Dapoer Poesat Noesantara Group"
    });
});

// Error handling middleware
app.use((error: any, req: Request, res: Response, next: NextFunction) => {
    res.status(error.status || 500).send({
        error: true,
        message: error.message || "Something Went Wrong!",
        data: {}
    });
});

app.listen(port, () => {
    console.log("Application Running on Port =", "localhost:2024", port);
});

module.exports = app;

